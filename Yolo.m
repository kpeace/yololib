/*
 yololib
 Inject dylibs into existing Mach-O binaries
 
 
 DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 Version 2, December 2004
 
 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
 
 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.
 
 DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
 
 0. You just DO WHAT THE FUCK YOU WANT TO.
 
 */

#import "Yolo.h"
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#define DYLIB_CURRENT_VER 0x10000
#define DYLIB_COMPATIBILITY_VERSION 0x10000

// load commands like to be aligned by long. 4 bytes for 32bit archs and 8 bytes for 64 bit archs. see mach-o/loader.h
#define ALIGNMENT_32_ARCH 4
#define ALIGNMENT_64_ARCH 8

#define MEM_BLOCK_SIZE      4096

@interface InsertionData : NSObject
@property long insertionPoint;
@property long endOfLoadCommands;
@end

@implementation InsertionData

@end

@implementation Yolo{
    int dylibCommandSize;
}

- (instancetype) initWithBinaryPath:(NSString *)binaryPath andDylibPath:(NSString *)dylibPath{
    if (self = [super init]){
        self.binaryPath = [binaryPath stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        self.dylibPath = [dylibPath stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    }
    
    return self;
}

- (void) setDylibPath:(NSString *)dylibPath{
    _dylibPath = [NSString stringWithFormat:@"@executable_path/%@", dylibPath];
    
}

- (void) addPadding:(FILE *)file ofSize:(long)size{
    if (size){
        char *padding = malloc(size);
        bzero(padding, size);
        
        fwrite(padding, size, 1, file);
        free(padding);
    }
}

// this should be calle only if we want to remove the signature. Removing a signature will invalid the app on iOS 9.0 and above
- (void) removeSignature:(FILE *)machoFile atOffset:(long)startMacho{
    NSLog(@"Searching for code signature");
    long startPos = ftell(machoFile);
    
    fseek(machoFile, startMacho, SEEK_SET);
    struct mach_header mach;
    
    fread(&mach, sizeof(struct mach_header), 1, machoFile);
    
    int loadCmdSize = sizeof(struct load_command);
    int loadSigCmdSize = sizeof(struct linkedit_data_command);
    struct load_command loadCmd;
    struct linkedit_data_command *sigCmd = nil;
    
    // go over load commands to find signature command
    
    for (int i = 0; (fread(&loadCmd, sizeof(struct load_command), 1, machoFile) != EOF) && (i < mach.ncmds); i++){
        if (LC_CODE_SIGNATURE == loadCmd.cmd){
            NSLog(@"Found load code signature command. Removing signature");
            
            // read load command as signature load command
            fseek(machoFile, -loadCmdSize, SEEK_CUR);
            
            sigCmd = malloc(sizeof(struct linkedit_data_command));
            fread(sigCmd, loadSigCmdSize, 1, machoFile);
            
            fseek(machoFile, -loadSigCmdSize, SEEK_CUR);
            [self addPadding:machoFile ofSize:loadSigCmdSize];
            
            fseek(machoFile, startMacho + sigCmd->dataoff, SEEK_SET);
            
            [self addPadding:machoFile ofSize:sigCmd->datasize];
            
            // remove number and size of load command in macho header
            NSLog(@"Original: load cmds num: %d, Size %d. Post instrumentation num: %d, size: %d", mach.ncmds, mach.sizeofcmds, (mach.ncmds - 1), (mach.sizeofcmds - loadSigCmdSize));
            mach.ncmds -= 1;
            mach.sizeofcmds -= loadSigCmdSize;
            
            fseek(machoFile, startMacho, SEEK_SET);
            fwrite(&mach, sizeof(struct mach_header), 1, machoFile);
            
            break;
        } else {
            fseek(machoFile, loadCmd.cmdsize - loadCmdSize, SEEK_CUR);
        }
    }
    
    // we didn't find a signature load command, nothing else to do
    if (sigCmd == nil) {
        fseek(machoFile, startPos, SEEK_SET);
        return;
    }
    
    // we found a signature command and deleted it, lets change the size of the __LINKEDIT command
    fseek(machoFile, startMacho + sizeof(struct mach_header), SEEK_SET);
    
    for (int i = 0; (fread(&loadCmd, sizeof(struct load_command), 1, machoFile) != EOF) && (i < mach.ncmds); i++){
        if (LC_SEGMENT == loadCmd.cmd){
            fseek(machoFile, -loadCmdSize, SEEK_CUR);
            
            struct segment_command segmentCmd;
            fread(&segmentCmd, sizeof(struct segment_command), 1, machoFile);
            
            if (strcmp(segmentCmd.segname, "__LINKEDIT") == 0) {
                NSLog(@"found __LINKEDIT load command");
                fseek(machoFile, -sizeof(struct segment_command), SEEK_CUR);
                
                segmentCmd.filesize -= sigCmd->datasize;
                
                // assuming that VM size is a multiple of 0x1000. seen in some ones elses code
                segmentCmd.vmsize = ceil((double)segmentCmd.filesize / 0x1000) * 0x1000;
                
                fwrite(&segmentCmd, sizeof(struct segment_command), 1, machoFile);
                
                break;
            } else {
                fseek(machoFile, loadCmd.cmdsize - sizeof(struct segment_command), SEEK_CUR);
            }
        } else if (LC_SEGMENT_64 == loadCmd.cmd) {
            NSLog(@"found LC_SEGMENT_64 load command");
            
            fseek(machoFile, -loadCmdSize, SEEK_CUR);
            
            struct segment_command_64 segmentCmd;
            fread(&segmentCmd, sizeof(struct segment_command_64), 1, machoFile);
            
            if (strcmp(segmentCmd.segname, "__LINKEDIT") == 0) {
                fseek(machoFile, -sizeof(struct segment_command_64), SEEK_CUR);
                
                segmentCmd.filesize -= sigCmd->datasize;
                segmentCmd.vmsize = ceil((double)segmentCmd.filesize / 0x1000) * 0x1000;
                
                fwrite(&segmentCmd, sizeof(struct segment_command), 1, machoFile);
                
                break;
            } else {
                fseek(machoFile, loadCmd.cmdsize - sizeof(struct segment_command_64), SEEK_CUR);
            }
        } else {
            fseek(machoFile, loadCmd.cmdsize - loadCmdSize, SEEK_CUR);
        }
    }
    
    free(sigCmd);
    fseek(machoFile, startPos, SEEK_SET);
}

- (void) jumpToLastDylibLoadCmd:(FILE *)machoFile{
    struct load_command loadCmd;
    bool inDylibLoadBlock = NO;
    
    // we only want to loop over the load commands but we should never continue the loop after we reached EOF
    while (fread(&loadCmd, sizeof(struct load_command), 1, machoFile) != EOF) {
        if (inDylibLoadBlock && !(loadCmd.cmd == LC_LOAD_DYLIB || loadCmd.cmd == LC_LOAD_WEAK_DYLIB)){
            // we passed the last LC_LOAD_DYLIB command
            
            fseek(machoFile, -sizeof(struct load_command), SEEK_CUR);
            
            NSLog(@"Found last LC_LOAD_DYLIB at offset: %ld", ftell(machoFile));
            
            break;
        } else if (!inDylibLoadBlock && (loadCmd.cmd == LC_LOAD_DYLIB || loadCmd.cmd == LC_LOAD_WEAK_DYLIB)){
            // we found the first LC_LOAD_DYLIB command
            inDylibLoadBlock = YES;
            
            NSLog(@"Found first LC_LOAD_DYLIB at offset: %ld", ftell(machoFile) - sizeof(struct load_command));
        }
        
        fseek(machoFile, (long)loadCmd.cmdsize - sizeof(struct load_command), SEEK_CUR);
        
    }
}

- (void) injectDylib32:(FILE *)machoFile atOffset:(uint32_t)top {
    fseek(machoFile, top, SEEK_SET);
    struct mach_header mach;
    
    fread(&mach, sizeof(struct mach_header), 1, machoFile);
    
    NSData* data = [self.dylibPath dataUsingEncoding:NSUTF8StringEncoding];
    
    uint32_t dylib_size = (uint32_t)[data length] + sizeof(struct dylib_command);
    
    // load commands like to be aligned by long. 4 bytes
    int padding_size = ALIGNMENT_32_ARCH - (dylib_size % ALIGNMENT_32_ARCH);
    dylib_size += padding_size;
    
    NSAssert((dylib_size % ALIGNMENT_32_ARCH) == 0, @"dylib command size must be aligned by 4 bytes for 32 bit archs");
    
    mach.ncmds += 1;
    uint32_t sizeofcmds = mach.sizeofcmds;
    mach.sizeofcmds += dylib_size;
    
    fseek(machoFile, -sizeof(struct mach_header), SEEK_CUR);
    fwrite(&mach, sizeof(struct mach_header), 1, machoFile);
    NSLog(@"Patching mach_header..\n");
    
    long startLdCmds = ftell(machoFile);
    [self jumpToLastDylibLoadCmd:machoFile];
    
    long sizeOfLdDylibCmds = ftell(machoFile) - startLdCmds;
    long sizeOfRemainingLdCMds = sizeofcmds - sizeOfLdDylibCmds;
    
    unsigned char *buffer = malloc(sizeOfRemainingLdCMds);
    
    // TODO better error handling
    if (fread(buffer, sizeOfRemainingLdCMds, 1, machoFile) != 1){
        NSLog(@"Error. Copyin didn;'t work. file will be corupted!");
    }
    
    fseek(machoFile, -sizeOfRemainingLdCMds, SEEK_CUR);
    
    struct dylib_command dyld;
    
    NSLog(@"Attaching dylib..\n\n");
    
    dyld.cmd = LC_LOAD_DYLIB;
    dyld.cmdsize = dylib_size;
    dyld.dylib.compatibility_version = DYLIB_COMPATIBILITY_VERSION;
    dyld.dylib.current_version = DYLIB_CURRENT_VER;
    dyld.dylib.timestamp = 2;
    dyld.dylib.name.offset = sizeof(struct dylib_command);
    
    fwrite(&dyld, sizeof(struct dylib_command), 1, machoFile);
    fwrite([data bytes], [data length], 1, machoFile);
    
    // add padding
    [self addPadding:machoFile ofSize:padding_size];
    
    // write the rest of the load commands.
    fwrite(buffer, sizeOfRemainingLdCMds, 1, machoFile);
    free(buffer);
    
    // TODO Do we need to add additional padding to compensate the added dylib load command?
}

- (void) injectDylib64:(FILE *)machoFile atOffset:(uint32_t)top{
    @autoreleasepool {
        fseek(machoFile, top, SEEK_SET);
        
        struct mach_header_64 mach;
        
        fread(&mach, sizeof(struct mach_header_64), 1, machoFile);
        
        NSData* data = [self.dylibPath dataUsingEncoding:NSUTF8StringEncoding];
        
        unsigned long dylib_size = sizeof(struct dylib_command) + [data length];
        
        // load commands like to be aligned by long. 8 bytes for 64 but archs
        int padding_size = ALIGNMENT_64_ARCH - (dylib_size % ALIGNMENT_64_ARCH);
        dylib_size += padding_size;
        
        NSAssert((dylib_size % ALIGNMENT_64_ARCH) == 0, @"dylib command size must be aligned by 8 bytes for 64 bit archs");
        
        NSLog(@"dylib size wow %lu", dylib_size);
        
        NSLog(@"mach.ncmds %u", mach.ncmds);
        
        mach.ncmds += 0x1;
        
        NSLog(@"mach.ncmds %u", mach.ncmds);
        
        uint32_t sizeofcmds = mach.sizeofcmds;
        mach.sizeofcmds += (dylib_size);
        
        NSLog(@"Patching mach_header..\n");
        
        // rewrite the macho header with new values
        fseek(machoFile, -sizeof(struct mach_header_64), SEEK_CUR);
        fwrite(&mach, sizeof(struct mach_header_64), 1, machoFile);
        
        long startLdCmds = ftell(machoFile);
        [self jumpToLastDylibLoadCmd:machoFile];
        
        long sizeOfLdDylibCmds = ftell(machoFile) - startLdCmds;
        long sizeOfRemainingLdCMds = sizeofcmds - sizeOfLdDylibCmds;
        
        unsigned char *buffer = malloc(sizeOfRemainingLdCMds);
        
        // TODO better error handling
        if (fread(buffer, sizeOfRemainingLdCMds, 1, machoFile) != 1){
            NSLog(@"Error. Copyin didn;t work. file will be corupted!");
        }
        
        fseek(machoFile, -sizeOfRemainingLdCMds, SEEK_CUR);
        
        struct dylib_command dyld;
        
        NSLog(@"Attaching dylib..\n\n");
        
        dyld.cmd = LC_LOAD_DYLIB;
        dyld.cmdsize = (uint32_t) dylib_size;
        dyld.dylib.compatibility_version = DYLIB_COMPATIBILITY_VERSION;
        dyld.dylib.current_version = DYLIB_CURRENT_VER;
        dyld.dylib.timestamp = 2;
        dyld.dylib.name.offset = sizeof(struct dylib_command);
        
        // write new dylib load command
        fwrite(&dyld, sizeof(struct dylib_command), 1, machoFile);
        fwrite([data bytes], [data length], 1, machoFile);
        
        // add padding
        [self addPadding:machoFile ofSize:padding_size];
        
        // write the rest of the load commands.
        fwrite(buffer, sizeOfRemainingLdCMds, 1, machoFile);
        free(buffer);
        
        // TODO Do we need to add additional padding to compensate the added dylib load command?
        
        
        NSLog(@"size %lu", sizeof(struct dylib_command) + [data length]);
        
    }
}

- (void) checkFilePathsCorrectness{
    if (self.binaryPath == nil || self.binaryPath.length <= 0) {
        @throw [NSException exceptionWithName:@"InvalidPath" reason:@"Path to binary is null or zero in lenght. A valid path to a binary file should be specified" userInfo:nil];
    }
    
    if (self.dylibPath == nil || self.dylibPath.length <= 0) {
        @throw [NSException exceptionWithName:@"InvalidPath" reason:@"Path to dylib is null or zero in lenght. A valid path to a dylib file should be specified" userInfo:nil];
    }
    
}

- (void) inject{
    // maybe we should use tmpfile(void)
    NSString *tempFilePath = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    
    NSLog(@"tmp file at location: %@", tempFilePath);
    
    // make sure every thing is set up propery
    [self checkFilePathsCorrectness];
    
    char buffer[4096], binary[4096], _dylib[4096];
    
    strlcpy(binary, [self.binaryPath UTF8String], sizeof(binary));
    strlcpy(_dylib, [self.dylibPath UTF8String], sizeof(self.dylibPath));
    
    NSLog(@"dylib path %@", self.dylibPath);
    FILE *binaryFile = fopen(binary, "rb+");
    printf("Reading binary: %s\n\n", binary);
    fread(&buffer, sizeof(buffer), 1, binaryFile);
    
    struct fat_header* fh = (struct fat_header*) (buffer);
    
    // TODO add support for i386 (CIGAM) and i386_64 (CIGAM_64) architectures.
    switch (fh->magic) {
        case FAT_MAGIC:
        case FAT_CIGAM:
        {
            // we are in a FAT file.
            NSLog(@"FAT binary!\n");
            
            struct fat_arch* arch = (struct fat_arch*) &fh[1];
            
            int i;
            for (i = 0; i < CFSwapInt32(fh->nfat_arch); i++) {
                NSLog(@"Injecting to arch %i\n", CFSwapInt32(arch->cpusubtype));
                if (CFSwapInt32(arch->cputype) == CPU_TYPE_ARM64) {
                    NSLog(@"64bit arch wow");
                    [self injectDylib64:binaryFile atOffset:CFSwapInt32(arch->offset)];
                }
                else {
                    [self injectDylib32:binaryFile atOffset:CFSwapInt32(arch->offset)];
                }
                arch++;
            }
            break;
        }
        case MH_MAGIC_64:
        case MH_CIGAM_64:
        {
            NSLog(@"Thin 64bit binary!\n");
            [self injectDylib64:binaryFile atOffset:0];
            break;
        }
        case MH_MAGIC:
        case MH_CIGAM:
        {
            NSLog(@"Thin 32bit binary!\n");
            [self injectDylib32:binaryFile atOffset:0];
            break;
        }
        default:
        {
            printf("Error: Unknown architecture detected");
            exit(1);
        }
    }
    
    NSLog(@"complete!");
    fclose(binaryFile);
}

@end
