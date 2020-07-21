//pngasteg.c, PNG alpha channel steganography tool
//Anonymous, June 1989
//compile with (linux):   gcc -Ofast -s -o pngasteg pngasteg.c -lpng -lz
//             (windows): gcc -Ofast -s -o pngasteg.exe pngasteg.c -Iinclude -Llib -lpng12 -l:zlib1.dll
//dependencies: libpng (1.2.x), zlib (1.2.x)



#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <png.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32 //allows us to open stdin and stdout in binary mode on windows
#include <io.h>
#include <fcntl.h>
#endif

#define INTRO "pngasteg - tool for hiding messages/data in the PNG alpha channel\nAnonymous June 1989\n"
#define VERINFO "Version 0.2-experimental - Sept 25 2018 9:55PM EDT"
//#define MAGICNUM 0x706e676173746567llu //llu means unsigned long long (uint64)
#define MAGIC_SIZE 8 //64 bits magic / 8
#define HEADER_SIZE 12 //(64 bits magic # + 32 bits length) / 8
#define STDIN_BUFSIZE 1024 //buffer for stdin reads (fseek to end won't work)

#define ERROR_SUCCESS 0 //success
#define ERROR_OOM 1 //out of memory
#define ERROR_PNG_INTERNAL 2 //libpng internal error
#define ERROR_PNG_BADSIG 3 //bad signature on PNG
#define ERROR_IMG_TOO_SMALL 4 //image too small to hold our data
#define ERROR_BADPARAMS 5 //invalid command line parameters
#define ERROR_BADFILES 6 //file access denied, file not found, etc.
#define ERROR_BADMAGIC 7 //magic number invalid
#define ERROR_BADMSGLEN 8 //bad message/data length
#define ERROR_STDIN_FERROR 9 //error reading from stdin
#define ERROR_FILE_FERROR 10 //error with file IO

int MAGICNUM = 0;

typedef unsigned char byte;
struct byteArray {
    byte* ptr;
    long len; //limit is (2 ^ 31 - 1) bytes
};

struct imageData {
    byte error;
    png_bytepp row_ptrs;
    png_uint_32 width;
    png_uint_32 height;
};

inline void verInfo(void) {
    puts(INTRO);
    puts(VERINFO);
    printf("    Compiled with libpng %s; using libpng %s.\n",
      PNG_LIBPNG_VER_STRING, png_libpng_ver);
    printf("    Compiled with zlib %s; using zlib %s.\n",
      ZLIB_VERSION, zlib_version);
}

inline void usage(FILE* stream) {
    fputs(INTRO"\n", stream);
    fputs("Usage:    \n    pngasteg -e <in.png> <out.png> <msg_file> [bits_per_px] [key]\n    pngasteg -d <in.png> <msg_file_out> [bits_per_px] [key]\n    pngasteg [-h] [-v]\n\nbits_per_px: # of LSBs per pixel to change on alpha channel\n             Must be positive factor of 8, default is 1\nkey: repeated & truncated to message length and XOR'ed with message\n\nNOTE: alpha/transparency information may be lost in the output file\n", stream);
}

struct imageData readPNGtoMem(FILE* ifp) {
    byte sig[8];
    struct imageData dt;
    
    fread(sig, 1, 8, ifp);
    if (!png_check_sig(sig, 8)) {
        dt.error = ERROR_PNG_BADSIG; //invalid PNG signature
        return dt;
    }
    
    //let libpng create its own data struct (better cross version support)
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        dt.error = ERROR_OOM;  //out of memory
        return dt;
    }
    
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        dt.error = ERROR_OOM; //out of memory
        return dt;
    }
    
    if (setjmp(png_ptr->jmpbuf)) { //libpng's weird error handler
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        dt.error = ERROR_PNG_INTERNAL; //error has occurred during PNG read
        return dt;
    }
    
    //let's start actually reading the image
    png_init_io(png_ptr, ifp);
    png_set_sig_bytes(png_ptr, 8); //use 8 signature bytes (we verified earlier)
    png_read_info(png_ptr, info_ptr); //read info into the png info struct
    
    //define & populate info fields
    png_uint_32 width, height;
    int bit_depth, color_type;
    png_get_IHDR(png_ptr, info_ptr, &width, &height, &bit_depth, &color_type, NULL, NULL, NULL);
    
    //handle bit depth and color palette conversions so data is in 8-bit RGBA format in RAM
    if(bit_depth == 16)
        png_set_strip_16(png_ptr); //downconvert 16-bit to 8-bit color
    
    switch (color_type) {
        case PNG_COLOR_TYPE_PALETTE:
            png_set_palette_to_rgb(png_ptr); //convert custom palette to RGB
            png_set_filler(png_ptr, 0xff, PNG_FILLER_AFTER); //fill alpha with 0xff (255)
            break;
        case PNG_COLOR_TYPE_GRAY:
            if (bit_depth < 8) //PNG_COLOR_TYPE_GRAY_ALPHA --> always 8/16bit depth.
                png_set_expand_gray_1_2_4_to_8(png_ptr); //upconvert 1/2/4-bit to 8-bit color
            
            png_set_gray_to_rgb(png_ptr); //map grayscale to rgb
            png_set_filler(png_ptr, 0xff, PNG_FILLER_AFTER); //fill alpha with 0xff (255)
            break;
        case PNG_COLOR_TYPE_RGB:
            png_set_filler(png_ptr, 0xff, PNG_FILLER_AFTER); //fill alpha with 0xff (255)
            break;
        case PNG_COLOR_TYPE_GRAY_ALPHA:
            png_set_gray_to_rgb(png_ptr); //map grayscale to rgb
            break;
    }
    
    if(png_get_valid(png_ptr, info_ptr, PNG_INFO_tRNS))
        png_set_tRNS_to_alpha(png_ptr); //if possible, use palette/metadata for alpha
    
    png_read_update_info(png_ptr, info_ptr); //update read parameters (to apply above conversions)
    
    //allocate row pointers and populate with data
    png_bytepp row_pointers = malloc(sizeof(png_bytep) * height);
    if (!row_pointers) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        dt.error = ERROR_OOM; //out of memory
        return dt;
    }
    
    long y;
    for(y = 0; y < height; ++y) {
        row_pointers[y] = malloc(png_get_rowbytes(png_ptr, info_ptr));
        if (!row_pointers[y]) {
            for (--y; y >= 0; --y) //free all previous row pointers
                free(row_pointers[y]);
            free(row_pointers); //free main data structure
            png_destroy_read_struct(&png_ptr, NULL, NULL);
            dt.error = ERROR_OOM; //out of memory
            return dt;
        }
    }
    png_read_image(png_ptr, row_pointers);
    
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL); //clean up
    
    //prepare return values
    dt.row_ptrs = row_pointers;
    dt.width = width;
    dt.height = height;
    dt.error = ERROR_SUCCESS;
    
    return dt;
}

byte writePNGfromMem(FILE* ofp, struct imageData dt) {
    //let libpng create its own data struct (better cross version support)
    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr)
        return ERROR_OOM;  //out of memory
    
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return ERROR_OOM;  //out of memory
    }
        
    if (setjmp(png_ptr->jmpbuf)) { //libpng's weird error handler
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return ERROR_PNG_INTERNAL; //error has occurred during PNG write
    }
    
    //begin to write
    png_init_io(png_ptr, ofp);
    //output is 8bit (per channel), RGBA format, not interlaced
    png_set_IHDR(png_ptr, info_ptr,
                 dt.width, dt.height,
                 8,
                 PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png_ptr, info_ptr);
    png_write_image(png_ptr, dt.row_ptrs);
    
    png_write_end(png_ptr, NULL); //end write
    png_destroy_write_struct(&png_ptr, &info_ptr); //free write structures
    
    return ERROR_SUCCESS;
}

struct byteArray readStdinToMem(int headerGap) {
    struct byteArray out;
    byte* data = malloc(STDIN_BUFSIZE + headerGap); //allocate data array, leave gap for header
    if (!data) {
        out.len = -ERROR_OOM; //negative length conveys error
        return out;
    }
    
    long dataLen = headerGap, blkLen; //start data after header gap
    byte* buf = malloc(STDIN_BUFSIZE); //allocate temp buffer
    if (!buf) {
        out.len = -ERROR_OOM; //negative length conveys error
        free(data);
        return out;
    }
    
    //note: fread returns # of elements (n bytes each) read instead of # of bytes read
    //therefore, we're reading STDIN_BUFSIZE elements (each with size of 1 byte)
    while(blkLen = fread(buf, 1, STDIN_BUFSIZE, stdin)) { //set block length, read until EOF
        byte *old = data;
        long oldDataLen = dataLen;
        data = realloc(data, dataLen += blkLen); //increment size, reallocate data array with new size
        if(!data) { //it's all or nothing. if we partially fail, just give up
            out.len = -ERROR_OOM; //negative length conveys error
            free(old); //clean up if we fail
            free(buf);
            return out;
        }
        
        memcpy(data + oldDataLen, buf, blkLen); //append buffer contents into data array
    }
    
    free(buf); //free our temp buffer
    
    if(ferror(stdin)) { //it's all or nothing. if we partially fail, just give up
        out.len = -ERROR_STDIN_FERROR; //negative length conveys error
        free(data); //dispose of data array
        return out;
    }
    
    //populate output data struct and return
    out.ptr = data;
    out.len = dataLen;
    return out;
}

struct byteArray readToMem(FILE* ifp, int headerGap) {
    struct byteArray out;
    
    if (ifp == stdin)
        out = readStdinToMem(headerGap); //treat stdin as special case, fseek to end fails
    else {
        fseek(ifp, 0, SEEK_END);
        long fsize = ftell(ifp);
        fseek(ifp, 0, SEEK_SET); //equivalent to rewind(ifp)
        
        byte* buf = malloc(fsize + headerGap); //allocate extra space for header
        if (!buf) {
            out.len = -ERROR_OOM; //use negative lengths to convey error
            return out;
        }
        
        fread(buf + headerGap, fsize, 1, ifp); //leave pre-gap for header
        if (ferror(ifp)) {
            free(buf);
            out.len = -ERROR_FILE_FERROR; //use negative lengths to convey error
            return out;
        }
        
        out.len = headerGap + fsize; //account for header gap
        out.ptr = buf;
    }
    
    return out;
}

inline void rowPtrCleanup(struct imageData dt) {
    long y;
    for(y = 0; y < dt.height; ++y)
        free(dt.row_ptrs[y]);
    free(dt.row_ptrs);
}

inline long getRequiredPx(long msgLen, byte bpp) {
    int msgBits = msgLen * 8, px = msgBits / bpp; //bytes to bits, then integer division
    if (msgBits % bpp) //if remainder is non-zero, we need another pixel
        ++px;
    
    return px; //essentially ceil(msgLen * 8 / bpp)
}

inline byte mkLSBmask(byte bits) {
    return ((1 << bits) - 1); //(1 << n) - 1 = 2 ^ n - 1 = n 1's in binary
}

inline byte randBits(byte bits) {
    return rand() & mkLSBmask(bits); //set other bits to 0
}

byte encPngASteg(FILE* ifp, FILE* ofp, struct byteArray msg, byte bpp) {
    struct imageData dt = readPNGtoMem(ifp);
    if (dt.error != ERROR_SUCCESS)
        return dt.error; //something went wrong, relay the error
    
    //check if image is large enough to hold the data
    if (dt.height * dt.width < getRequiredPx(msg.len, bpp)) {
        rowPtrCleanup(dt);
        return ERROR_IMG_TOO_SMALL;
    }
    
    srand(time(NULL) ^ dt.height ^ dt.width); //seed rng (for noise appended after data)
    
    long x, y, byteIdx = 0;
    byte bitIdx = 0;
    for(y = 0; y < dt.height; ++y) {
        png_bytep row = dt.row_ptrs[y];
        for(x = 0; x < dt.width; ++x) {
            png_bytep px = &(row[x * 4]); //RGBA is 4 bytes (hence the "x * 4")
            byte msgBits;
            
            if (byteIdx < msg.len) { //we're still encoding data
                msgBits = ((msg.ptr[byteIdx] >> (8 - bitIdx - bpp)) & mkLSBmask(bpp)); //extract "bpp" bits from data at current pos
                
                if ((bitIdx += bpp) == 8) { //move on to next byte
                    ++byteIdx;
                    bitIdx = 0; //reset bit index
                }
            }
            else //encode random noise for rest of image
                msgBits = randBits(bpp);
            
            px[3] = (px[3] & ~mkLSBmask(bpp)) | msgBits; //replace "bpp" LSBs on alpha channel
        }
    }
    
    byte retVal = writePNGfromMem(ofp, dt);
    if (retVal != ERROR_SUCCESS) {
        rowPtrCleanup(dt);
        return retVal; //something went wrong, relay the error
    }
    
    //clean up
    rowPtrCleanup(dt);
    return ERROR_SUCCESS;
}

struct byteArray decPngASteg(FILE* ifp, byte bpp) {
    struct byteArray out;
    
    struct imageData dt = readPNGtoMem(ifp);
    if (dt.error != ERROR_SUCCESS) {
        out.len = -dt.error; //encode error as negative length
        return out; //something went wrong, relay the error
    }
    
    byte* header = calloc(HEADER_SIZE, sizeof(byte)); //allocate and zero fill block
    byte* outBuf;
    
    if (!header) {
        rowPtrCleanup(dt);
        out.len = -ERROR_OOM; //encode error as negative length
        return out; //something went wrong, relay the error
    }
    
    long x, y, byteIdx = 0;
    byte bitIdx = 0, done = 0;
    unsigned long realLen = 0, maxLen = dt.height * dt.width * bpp / 8;
    
    if (maxLen < HEADER_SIZE) { //image can't even hold our header, don't decode
        rowPtrCleanup(dt);
        out.len = -ERROR_IMG_TOO_SMALL; //encode error as negative length
        return out; //something went wrong, relay the error
    }
    
    for(y = 0; y < dt.height; ++y) {
        png_bytep row = dt.row_ptrs[y];
        for(x = 0; x < dt.width; ++x) {
            png_bytep px = &(row[x * 4]); //RGBA is 4 bytes (hence the "x * 4")
            if (byteIdx < HEADER_SIZE)
                header[byteIdx] |= (px[3] & mkLSBmask(bpp)) << (8 - bitIdx - bpp);
            else { //handle header, then process real data
                if (byteIdx == HEADER_SIZE && bitIdx == 0) {
                    //process header to get magic number and size
                    int i;
                    unsigned long long magic = 0;
                    for (i = 0; i < MAGIC_SIZE; ++i) //reconstruct magic number
                        magic |= (unsigned long long)header[i] << ((MAGIC_SIZE - i - 1) * 8);
                    
                    /*if (magic != MAGICNUM) {
                        fprintf(stderr, "DEBUG: bad magic #: %llu, expected %llu\n", magic, MAGICNUM); //TODO: actually error out here
                        fputs("DEBUG: Dazed and confused, but trying to continue, fixme: cleanup & exit here\n", stderr);
                    }*/
                    
                    byte lenBytes = HEADER_SIZE - MAGIC_SIZE;
                    for (i = 0; i < lenBytes; ++i) //reconstruct real data size
                        realLen |= (unsigned long)header[MAGIC_SIZE + i] << ((lenBytes - i - 1) * 8);
                    
                    unsigned long maxDtLen = maxLen - HEADER_SIZE;
                    if (realLen > maxDtLen) { //invalid/corrupted input file?
                        fprintf(stderr, "DEBUG: bad data length: %lu, max possible is %lu\n", realLen, maxDtLen); //TODO: actually error out here
                        fputs("DEBUG: clamping length to max value, fixme: cleanup & exit here\n", stderr);
                        realLen = maxDtLen;
                    }
                    
                    outBuf = calloc(realLen + HEADER_SIZE, sizeof(byte)); //allocate and zero fill block
                    if (!outBuf) {
                        rowPtrCleanup(dt);
                        out.len = -ERROR_OOM; //encode error as negative length
                        free(header);
                        return out; //something went wrong, relay the error
                    }
                    
                    memcpy(outBuf, header, HEADER_SIZE); //copy header to output buffer
                    free(header); //expunge header
                }
                
                if (byteIdx == realLen + HEADER_SIZE) {
                    done = 1;
                    break;
                }
                
                //process real data
                outBuf[byteIdx] |= (px[3] & mkLSBmask(bpp)) << (8 - bitIdx - bpp);
            }
            
            if ((bitIdx += bpp) == 8) { //next byte
                ++byteIdx;
                bitIdx = 0; //reset bit index
            }
        }
        if (done)
            break;
    }
    
    //clean up
    rowPtrCleanup(dt);
    
    //populate return struct
    out.len = realLen + HEADER_SIZE;
    out.ptr = outBuf;
    return out;
}

void xorEncBytes(struct byteArray msg, long headerSize, char* key) {
    int i, keyIdx = 0, keyLen = strlen(key);
    for (i = headerSize; i < msg.len; ++i) { //skip over "header" bytes
        msg.ptr[i] ^= key[keyIdx]; //XOR is symmetric, (a ^ b) ^ b = a
        if (++keyIdx == keyLen) //increment key pos, treat key like a cyclic structure
            keyIdx = 0; //we've hit the end of the key, loop around
    }
}

int main(int argc, char** argv) {
    int finalRetVal = ERROR_SUCCESS; //final return value for program
    
#ifdef _WIN32 //open stdout and stdin in binary mode on Windows
    setmode(fileno(stdout), O_BINARY);
    setmode(fileno(stdin), O_BINARY);
#endif
    
    srand(time(NULL));
    MAGICNUM = ((unsigned long long)rand()) * ((unsigned long long)rand()) * ((unsigned long long)rand()) * ((unsigned long long)rand());
    
    if (argc - 1 == 0) {
        usage(stderr);
        return ERROR_BADPARAMS;
    }
    if (strcmp(argv[1], "-v") == 0) {
        verInfo();
        return ERROR_SUCCESS;
    }
    if (strcmp(argv[1], "-h") == 0) {
        usage(stdout);
        return ERROR_SUCCESS;
    }
        
    if (strcmp(argv[1], "-e") == 0) {
        if (argc - 1 < 4 || argc - 1 > 6) {
            usage(stderr);
            return ERROR_BADPARAMS;
        }
        
        int bpp = 1;
        if (argc - 1 >= 5)
            bpp = atoi(argv[5]);
        if (bpp < 1 || 8 % bpp != 0) {
            fputs("ERROR: bits_per_px must be positive factor of 8\n", stderr);
            return ERROR_BADPARAMS;
        }
        
        FILE* ifp = fopen(argv[2], "rb");
        if (!ifp) {
            fputs("ERROR: unable to open image input\n", stderr);
            return ERROR_BADFILES;
        }
        
        FILE* msgfp = (strcmp(argv[4], "-") == 0) ? stdin : fopen(argv[4], "rb"); //"-" means stdin here
        if (!msgfp) {
            fputs("ERROR: unable to open message input\n", stderr);
            fclose(ifp);
            return ERROR_BADFILES;
        }
        
        FILE* ofp = fopen(argv[3], "wb");
        if (!ofp) {
            fputs("ERROR: unable to write to output image file\n", stderr);
            if (msgfp != stdin)
                fclose(msgfp); //don't close stdin
            fclose(ifp);
            return ERROR_BADFILES;
        }
        
        struct byteArray msg = readToMem(msgfp, HEADER_SIZE); //read to byte array, leave gap for header
        if (msg.len < 0) { //we've got an error
            byte retVal = finalRetVal = -msg.len;
            fprintf(stderr, "DEBUG: data file read failed, cleanup and exit in progress, error code: %u\n", retVal); //TODO: handle error(s)
        }
        else {
            if (argc - 1 == 6)
                xorEncBytes(msg, HEADER_SIZE, argv[6]); //don't XOR encode the header
            
            //put header in prefix gap
            int i, lenBytes = HEADER_SIZE - MAGIC_SIZE, realLen = msg.len - HEADER_SIZE;
            for (i = 0; i < MAGIC_SIZE; ++i)
                msg.ptr[i] = (MAGICNUM >> (MAGIC_SIZE - 1 - i) * 8) & mkLSBmask(8); //split magic number into single bytes
            
            for (i = 0; i < lenBytes; ++i)
                msg.ptr[MAGIC_SIZE + i] = (realLen >> (lenBytes - 1 - i) * 8) & mkLSBmask(8); //split length variable into single bytes
            
            byte retVal = encPngASteg(ifp, ofp, msg, bpp);
            if (retVal != ERROR_SUCCESS) {
                finalRetVal = retVal;
                fprintf(stderr, "DEBUG: encode failed, cleanup and exit in progress, error code: %u\n", retVal); //TODO: handle error(s)
            }
            
            free(msg.ptr);
        }
        if (msgfp != stdin) //don't close stdin
            fclose(msgfp);
        fclose(ifp);
        fclose(ofp);
    }
    else if (strcmp(argv[1], "-d") == 0) {
        if (argc - 1 < 3 || argc - 1 > 5) {
            usage(stderr);
            return ERROR_BADPARAMS;
        }
        
        int bpp = 1;
        if (argc - 1 >= 4)
            bpp = atoi(argv[4]);
        if (bpp < 1 || 8 % bpp != 0) {
            fputs("ERROR: bits_per_px must be positive factor of 8\n", stderr);
            return ERROR_BADPARAMS;
        }
    
        FILE* ifp = fopen(argv[2], "rb");
        if (!ifp) {
            fputs("ERROR: unable to open image input\n", stderr);
            return ERROR_BADFILES;
        }
        
        FILE* msgofp = (strcmp(argv[3], "-") == 0) ? stdout : fopen(argv[3], "wb"); //"-" means stdout here
        if (!msgofp) {
            fclose(ifp);
            fputs("ERROR: unable to open message output\n", stderr);
            return ERROR_BADFILES;
        }
        
        struct byteArray msg = decPngASteg(ifp, bpp);
        
        if (msg.len < 0) {
            byte retVal = finalRetVal = -msg.len; //we're using negative lengths to convey errors
            fprintf(stderr, "DEBUG: decode failed, cleanup and exit in progress, error code: %u\n", retVal); //TODO: handle error(s)
        }
        else {
            if (argc - 1 == 5)
                xorEncBytes(msg, HEADER_SIZE, argv[5]); //don't XOR decode the header
            
            fwrite(msg.ptr + HEADER_SIZE, msg.len - HEADER_SIZE, 1, msgofp); //strip off header, write to output
            free(msg.ptr);
            if (ferror(msgofp)) {
                fputs("ERROR: unable to write to message output\n", stderr);
                finalRetVal = ERROR_FILE_FERROR;
            }
        }
        
        fclose(ifp);
        if (msgofp != stdout) //don't close stdout
            fclose(msgofp);
    }
    else {
        fputs("ERROR: Invalid operation. Must be -d (decode) or -e (encode).\n", stderr);
        return ERROR_BADPARAMS;
    }
    
    return finalRetVal;
}
