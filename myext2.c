#include <stdio.h>
#include "myext2.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/** global var **/

myext2_group_desc group_desc;

uint16_t root_dir_inode_id;
uint16_t current_file_inode_id;
uint16_t current_dir_inode_id;
char global_path[MYEXT2_NAME_LENGTH] = "/";

FILE *fp;

cache_dir_entry *root;
cache_dir_entry *current_dir_cache;
uint64_t inode_bitmap[BLOCK_SIZE/8] = {0};
uint64_t block_bitmap[BLOCK_SIZE/8] = {0};

/** functions **/

/** fs **/
int fs_init();
int fs_is_exists();
int fs_create(char *volume_name, char *psw);
int fs_delete();
int fs_load_global();
int fs_command_loop();
int fs_close();

/** file **/
int is_file(uint16_t inode_id, myext2_inode *inode, char *file_name);
int file_is_exists(uint16_t inode_id, myext2_inode *inode, char *file_name);
int file_create(uint16_t inode_id, myext2_inode *inode, char *file_name);
int file_delete(uint16_t inode_id, myext2_inode *inode, char *file_name);
int file_write(uint16_t inode_id, myext2_inode *inode, char *file_name, char *buff, uint32_t size);
int file_read(uint16_t inode_id, myext2_inode *inode, char *file_name, char *buff, uint32_t size);
int file_size(uint16_t inode_id, myext2_inode *inode, char *file_name);

/** dir **/
int is_dir(uint16_t inode_id, myext2_inode *inode, char *file_name);
int is_current_dir(uint16_t inode_id, myext2_inode *inode, char *file_name);
int dir_is_exists(uint16_t inode_id, myext2_inode *inode, char *file_name);
int dir_create(uint16_t inode_id, myext2_inode *inode, char *file_name);
int dir_delete(uint16_t inode_id, myext2_inode *inode, char *file_name);
int dir_info(uint16_t inode_id, myext2_inode *inode);
int dir_child(uint16_t inode_id, myext2_inode *inode, char *file_name, myext2_inode *child);
int dir_root_create();

/** inode **/
int get_empty_inode();
int inode_alloc(uint16_t inode_id);
int inode_free(uint16_t inode_id);
int inode_write(uint16_t inode_id, myext2_inode *inode);
int inode_read(uint16_t inode_id, myext2_inode *inode);
int inode_init(myext2_inode *inode);
int inode_block_write(uint16_t inode_id, myext2_inode *inode, char *data, uint32_t data_size);
int inode_block_read(uint16_t inode_id, myext2_inode *inode, char *data, uint32_t data_size);
int inode_block_free(uint16_t inode_id, myext2_inode *inode, uint16_t num);
int inode_block_alloc(uint16_t inode_id, myext2_inode *inode, uint16_t num);
int inode_block_append(uint16_t inode_id, myext2_inode *inode, char *data, uint32_t data_size, uint32_t offset);
int inode_block_get_block_by_num(uint16_t inode_id, myext2_inode *inode, uint32_t block_num);
int inode_root(myext2_inode *inode);

/** block **/
int get_empty_block();
int block_alloc(uint16_t block_id);
int block_free(uint16_t block_id);
int block_write(uint16_t block_id, char *data, uint16_t data_size);
int block_append(uint16_t block_id, char *data, uint16_t data_size, uint16_t offset);
int block_read(uint16_t block_id, char *data, uint16_t data_size);
int block_init(myext2_inode *inode);
int block_get_num_by_file_size(uint32_t file_size);

/** dir cache **/
int dir_cache_load();
int dir_cache_free();
int dir_cache_read_inode_by_path(char *file_name, myext2_inode *inode);

/** path **/
int path_pwd(uint16_t inode_id, char *path);

/** ui **/

int fs_start();

/** api **/

int myext2_format() {

    printf("FS Formating...\n");
    /** remove if exists **/
    if (fs_is_exists(PATH) == 0) {
        fs_delete(PATH);
    }
    /** filled with 0 **/
    fp = fopen(PATH, "w+");
    if (fp == NULL) {
        printf("FS Format Error, Exiting...\n");
        return -1;
    }
    /** init fs **/
    printf("Disk Init, Please Input Volume Name\n");
    char volume_name[16];
    scanf("%s", volume_name);
    printf("Input Your Password\n");
    char psw[24];
    scanf("%s", psw);
    fs_create(volume_name, psw);

    dir_root_create();

}

int myext2_password() {
    char psw[16];
    int flag = 1;
    while (flag) {
        printf("Input old password: ");
        scanf("%s", psw);
        if (strcmp(group_desc.psw, psw) == 0) {
            flag = 0;
        } else {
            char is_retry = ' ';
            printf("Password not valid, retry ? (Y/N)\n");
            while (is_retry == ' ' || is_retry == '\n') scanf("%c", &is_retry);
            if (is_retry != 'Y' && is_retry != 'y') {
                return 0;
            }
        }
    }
    printf("Input new password: ");
    scanf("%s", psw);
    strcpy(group_desc.psw, psw);
    rewind(fp);
    fwrite(&group_desc, sizeof(group_desc), 1, fp);
    fflush(fp);
    printf("Password modified success.\n");
}

int myext2_ls() {
    myext2_inode current_dir_inode;
    inode_read(current_dir_inode_id, &current_dir_inode);
    #ifdef DEBUG
        printf("[myext2_ls] current_dir_inode_id = %d, current_dir_inode->i_size = %d\n", current_dir_inode_id, current_dir_inode.i_size);
    #endif
    return dir_info(current_dir_inode_id, &current_dir_inode);
}

int myext2_create() {
    char type = ' ';
    char file_name[MYEXT2_NAME_LENGTH];
    while (type == ' ' || type == '\n') scanf("%c", &type);
    scanf("%s", file_name);
    myext2_inode current_dir_inode;
    inode_read(current_dir_inode_id, &current_dir_inode);
    if (type == 'd') {
        dir_create(current_dir_inode_id, &current_dir_inode, file_name);
    } else if (type == 'f') {
        file_create(current_dir_inode_id, &current_dir_inode, file_name);
    } else {
        printf("Invalid File Type.\n");
    }
    return 0;
}

int myext2_delete() {
    char type = ' ';
    char file_name[MYEXT2_NAME_LENGTH];
    while (type == ' ' || type == '\n') scanf("%c", &type);
    scanf("%s", file_name);
    myext2_inode current_dir_inode;
    inode_read(current_dir_inode_id, &current_dir_inode);
    if (type == 'd') {
        dir_delete(current_dir_inode_id, &current_dir_inode, file_name);
    } else if (type == 'f') {
        file_delete(current_dir_inode_id, &current_dir_inode, file_name);
    } else {
        printf("Invalid File Type.\n");
    }
    return 0;
}

int myext2_cd() {
    char path[1024];
    char tmp_path[MYEXT2_NAME_LENGTH];
    scanf("%s", path);
    #ifdef DEBUG
        printf("[myext2_cd] path = %s\n", path);
    #endif // DEBUG
    char *p = path;
    uint16_t tmp_inode_id;
    myext2_inode tmp_inode;
    if (p[0] == '/') {
        ++p;
        strcpy(tmp_path, "/");
        tmp_inode_id = root_dir_inode_id;
    } else {
        strcpy(tmp_path, global_path);
        tmp_inode_id = current_dir_inode_id;
    }
    inode_read(tmp_inode_id, &tmp_inode);    
    char *file_name = strtok(p, "/");
    while (file_name != NULL) {
        tmp_inode_id = dir_child(tmp_inode_id, &tmp_inode, file_name, &tmp_inode);
        if (tmp_inode_id < 0) {
            printf("Invalid path '%s'.\n", path);
            return 0;
        }
        #ifdef DEBUG
            printf("[myext2_cd] file_name = %s, tmp_inode_id = %d\n", file_name, tmp_inode_id);
        #endif // DEBUG
        strcpy(tmp_path, file_name);
        file_name = strtok(NULL, "/");
    }
    #ifdef DEBUG
        printf("[myext2_cd] tmp_inode.i_mode = %d\n", tmp_inode.i_mode);
    #endif // DEBUG
    if (tmp_inode.i_mode == FILE_TYPE_DIR) {
        current_dir_inode_id = tmp_inode_id;
        strcpy(global_path, tmp_path);
    } else {
        printf("'%s' is not a dir.\n", tmp_path);
    }
    return 0;
}

int myext2_close() {

}

int myext2_read() {
    char file_name[MYEXT2_NAME_LENGTH];
    scanf("%s", file_name);
    myext2_inode current_dir_inode;
    inode_read(current_dir_inode_id, &current_dir_inode);
    int size = file_size(current_dir_inode_id, &current_dir_inode, file_name);
    if (size < 0) {
        printf("No file named '%s'.", file_name);
    } else {
        char *buff = (char *)malloc(size+1);
        file_read(current_dir_inode_id, &current_dir_inode, file_name, buff, size);
        buff[size] = '\0';
        printf("%s", buff);
        free(buff);
    }
    return 0;
}

int myext2_write() {
    char file_name[MYEXT2_NAME_LENGTH];
    scanf("%s", file_name);
    printf("Write to file '%s', press `ESC` to finish input.\n", file_name);
    int size = 10;
    int index = 0;
    char c;
    char *buff = (char *)malloc(size);
    while ((c = getchar()) != '\n');
    while ((c = getchar()) != 0x1B) {
        if (index+1 >= size) {
            buff = (char *)realloc(buff, size*2);
            size *= 2;
        }
        buff[index++] = c;
    }
    if (index+1 >= size) {
        buff = (char *)realloc(buff, size+1);
    }
    buff[index++] = '\0';
    myext2_inode current_dir_inode;
    inode_read(current_dir_inode_id, &current_dir_inode);
    file_write(current_dir_inode_id, &current_dir_inode, file_name, buff, index);
    free(buff);
    return 0;
}

int myext2_exit() {
    printf("Exiting...\n");
    exit(0);
}

/** main **/

int test() {
    // printf("%d\n", sizeof(group_desc));
    // printf("%d\n", sizeof(inode));
    // printf("%d\n", sizeof(dir_entry));
    printf("%d\n", sizeof(myext2_inode));
}

int main(void) {
    fs_start();
    // test();
}

/** implements **/

/** ui **/

int fs_start() {

    int flag = 0;

    /** fs init **/
    flag = fs_init();

    /** fs command loop **/
    if (flag >= 0) fs_command_loop();

    /** fs close **/
    fs_close();
    
}

/** fs **/

int fs_init() {
    printf("LFS Starting...\n");
    /** is fs exists **/
    int is_exists = fs_is_exists();
    if (is_exists < 0) {
        /** create fs **/
        printf("LFS Not Exists, Format Now ? (Y/N)\n");
        char is_fmt;
        scanf("%c", &is_fmt);
        if (is_fmt == 'Y' || is_fmt == 'y') {
            myext2_format();
            fs_load_global();
        } else {
            printf("Abort, Exiting...\n");
            return -1;
        }
    } else {
        /** load fs **/
        fp = fopen(PATH, "r+");
        if (fp == NULL) {
            printf("Open FS Failed, Exiting...\n");
            return -1;
        }
        fs_load_global();
        while (1) {
            printf("Load FS Success, Please Input Your Password: ");
            char psw[16];
            scanf("%s", psw);
            if (strcmp(psw, group_desc.psw) == 0) {
                printf("Login Success\n");
                break;
            }
            printf("Password Invalid, Retry ? (Y/N)\n");
            char is_retry = ' ';
            while (is_retry == ' ' || is_retry == '\n') scanf("%c", &is_retry);
            if (is_retry != 'Y' && is_retry != 'y') {
                printf("Abort, Exiting...\n");
                return -1;
            }
        }
    }
    return 0;
}

int fs_is_exists() {
    return access(PATH, 0);
}

int fs_create(char *volume_name, char *psw) {
    uint16_t zero_size_64 = BLOCK_SIZE / 8;
    uint64_t zero[zero_size_64];
    memset(zero, 0, sizeof(zero));
    for (uint16_t i = 0; i < BLOCKS; ++i) {
        fseek(fp, i*BLOCK_SIZE, SEEK_SET);
        fwrite(zero, sizeof(zero), 1, fp);
    }
    fflush(fp);
    strcpy(group_desc.bg_volume_name, volume_name);
    group_desc.bg_inode_bitmap = 1;
    group_desc.bg_block_bitmap = 2;
    group_desc.bg_inode_table = 3;
    group_desc.bg_free_blocks_count = BLOCK_SIZE * 8;
    group_desc.bg_free_inodes_count = BLOCK_SIZE * 8;
    group_desc.bg_used_dirs_count = 0;
    strcpy(group_desc.psw, psw);
    fseek(fp, 0, SEEK_SET);
    fwrite(&group_desc, sizeof(group_desc), 1, fp);
    fflush(fp);
}

int fs_delete() {
    return remove(PATH);
}

int fs_load_global() {
    rewind(fp);
    fread(&group_desc, sizeof(group_desc), 1, fp);
    fseek(fp, BLOCK_SIZE, SEEK_SET);
    fread(inode_bitmap, sizeof(inode_bitmap), 1, fp);
    fseek(fp, 2*BLOCK_SIZE, SEEK_SET);
    fread(block_bitmap, sizeof(block_bitmap), 1, fp);
    root_dir_inode_id = current_dir_inode_id = 1;
}

int fs_command_loop() {
    int flag = 1;

    /** command **/
    char command[16];
    uint8_t matched;
    while (flag >= 0) {
        printf("[lorin@lorin-pc]:%s$ ", global_path);
        scanf("%s", &command);
        matched = 0;
        for (uint8_t i = 0; i < COMMAND_SIZE; ++i) {
            if (strcmp(command, commands[i]) == 0) {
                switch (i) {
                    case COMMAND_FORMAT:
                        flag = myext2_format();
                        break; 
                    case COMMAND_PASSWORD:
                        flag = myext2_password();
                        break;
                    case COMMAND_LS:
                        flag = myext2_ls();
                        break;
                    case COMMAND_CREATE:
                        flag = myext2_create();
                        break;
                    case COMMAND_DELETE:
                        flag = myext2_delete();
                        break;
                    case COMMAND_CD:
                        flag = myext2_cd();
                        break;
                    case COMMAND_CLOSE:
                        flag = myext2_close();
                        break;
                    case COMMAND_READ:
                        flag = myext2_read();
                        break;
                    case COMMAND_WRITE:
                        flag = myext2_write();
                        break;
                    case COMMAND_EXIT:
                        flag = myext2_exit();
                        break;
                    default:
                        printf("Invalid Command '%s', Retry. \n", command);
                        break;
                }
                matched = 1;
                break;
            }
        }
        if (! matched) {
            printf("Invalid Command '%s', Retry. \n", command);            
        }
    }
}

int fs_close() {
    if (fp != NULL) fclose(fp);
}

/** inode **/

int get_empty_inode() {
    int array_index = 0;
    int bit_index = 0;
    for (int i = 0; i < TWO_INDEX_BLOCKS; ++i) {
        array_index = i / 64;
        bit_index = i % 64;
        if (! (inode_bitmap[array_index] & (1L << (63-bit_index)))) {
            return i+1;
        }
    }
    return -1;
}

int inode_alloc(uint16_t inode_id) {
    int array_index = (inode_id-1) / 64;
    int bit_index = (inode_id-1) % 64;
    if (inode_bitmap[array_index] & (1L << (63-bit_index))) return -1;
    inode_bitmap[array_index] |= (1L << (63-bit_index));
    #ifdef DEBUG
        printf("[inode_alloc] array_index = %d, bit_index = %d, | = %llx\n", array_index, bit_index, (1L << (63-bit_index)));
        printf("[inode_alloc] inode_bitmap[array_index] = %llx\n", inode_bitmap[array_index]);
    #endif
    fseek(fp, BLOCK_SIZE, SEEK_SET);
    fwrite(inode_bitmap, sizeof(inode_bitmap), 1, fp);
    --group_desc.bg_free_inodes_count;
    fseek(fp, 0, SEEK_SET);
    fwrite(&group_desc, sizeof(group_desc), 1, fp);
    fflush(fp);
    return 0;
}

int inode_free(uint16_t inode_id) {
    int array_index = (inode_id-1) / 64;
    int bit_index = (inode_id-1) % 64;
    if (! (inode_bitmap[array_index] & (1L << (63-bit_index)))) return 0;
    inode_bitmap[array_index] &= (~(1L << (63-bit_index)));
    fseek(fp, BLOCK_SIZE, SEEK_SET);
    fwrite(inode_bitmap, sizeof(inode_bitmap), 1, fp);
    ++group_desc.bg_free_inodes_count;
    fseek(fp, 0, SEEK_SET);
    fwrite(&group_desc, sizeof(group_desc), 1, fp);
    fflush(fp);
    return 0;
}

int inode_write(uint16_t inode_id, myext2_inode *inode) {
    if (inode == NULL) return -1;
    fseek(fp, 3*BLOCK_SIZE+(inode_id-1)*INODE_SIZE, SEEK_SET);
    fwrite(inode, sizeof(myext2_inode), 1, fp);
    fflush(fp);
    return 0;
}

int inode_read(uint16_t inode_id, myext2_inode *inode) {
    if (inode == NULL) return -1;
    fseek(fp, 3*BLOCK_SIZE+(inode_id-1)*INODE_SIZE, SEEK_SET);
    fread(inode, sizeof(myext2_inode), 1, fp);
    return 0;
}

int inode_init(myext2_inode *inode) {
    if (inode == NULL) return -1;
    memset(inode, 0, sizeof(myext2_inode));
    return 0;
}

int inode_root(myext2_inode *inode) {
    if (inode == NULL) return -1;
    fseek(fp, 3*BLOCK_SIZE, SEEK_SET);
    fread(inode, sizeof(inode), 1, fp);
    return 0;
}

int inode_block_read(uint16_t inode_id, myext2_inode *inode, char *data, uint32_t data_size) {
    if (inode == NULL || data == NULL) return -1;
    if (data_size > inode->i_size) data_size = inode->i_size;
    int read_data_size = data_size;
    int read_block = 0;
    int read_block_id = 0;
    char *read_data = data;
    while (read_data_size > 0) {
        read_block_id = inode_block_get_block_by_num(inode_id, inode, read_block);
        ++read_block;
        int tmp_read_data_size = (read_data_size > BLOCK_SIZE) ? BLOCK_SIZE : read_data_size;
        block_read(read_block_id, read_data, tmp_read_data_size);
        read_data_size -= tmp_read_data_size;
        read_data += tmp_read_data_size;
    }
    return 0;
}

int inode_block_write(uint16_t inode_id, myext2_inode *inode, char *data, uint32_t data_size) {
    return inode_block_append(inode_id, inode, data, data_size, 0);
}

int inode_block_append(uint16_t inode_id, myext2_inode *inode, char *data, uint32_t data_size, uint32_t offset) {
    if (inode == NULL || data == NULL) return -1;
    int file_size = data_size + offset;
    #ifdef DEBUG
        printf("[inode_block_append] file_size = %d\n", file_size);
    #endif
    if (file_size > TWO_INDEX_LIMIT) return -1;
    int blocks = block_get_num_by_file_size(file_size);
    #ifdef DEBUG
        printf("[inode_block_append] blocks = %d\n", blocks);
    #endif
    if (blocks < inode->i_blocks) {
        inode_block_free(inode_id, inode, inode->i_blocks-blocks);
        #ifdef DEBUG
            printf("[inode_block_append] inode_block_free, blocks = %d, inode_blocks = %d\n", blocks, inode->i_blocks);
        #endif
    } else if (blocks > inode->i_blocks) {
        inode_block_alloc(inode_id, inode, blocks-inode->i_blocks);
        #ifdef DEBUG
            printf("[inode_block_append] inode_block_alloc, blocks = %d, inode_blocks = %d\n", blocks, inode->i_blocks);
        #endif
    }
    /** find where to append **/
    int write_block = offset / BLOCK_SIZE;
    int write_offset = offset % BLOCK_SIZE;
    int write_data_size =  data_size;
    int write_block_id = 0;
    char *write_data = data;
    while (write_data_size > 0) {
        write_block_id = inode_block_get_block_by_num(inode_id, inode, write_block);
        #ifdef DEBUG
            printf("[inode_block_append] write_block_id = %d\n", write_block_id);
        #endif
        int tmp_write_data_size = (write_data_size > (BLOCK_SIZE - write_offset)) ? BLOCK_SIZE-write_offset : write_data_size;
        block_append(write_block_id, write_data, tmp_write_data_size, write_offset);
        write_offset = 0;
        write_data_size -= tmp_write_data_size;
        write_data += tmp_write_data_size;
        ++write_block;
    }
    inode->i_size = file_size;
    inode_write(inode_id, inode);
    return 0;
}

int inode_block_free(uint16_t inode_id, myext2_inode *inode, uint16_t num) {
    if (inode == NULL) return -1;
    if (num >= inode->i_blocks) {
        /** free direct index **/
        int direct_index = (num <= DIRECT_INDEX_BLOCKS) ? num : DIRECT_INDEX_BLOCKS;
        for (int i = 0; i < direct_index; ++i) {
            block_free(inode->i_block[i]);
            inode->i_block[i] = 0;
        }
        /** free one index **/
        int one_index = (num-DIRECT_INDEX_BLOCKS > ONE_INDEX_BLOCKS) ? ONE_INDEX_BLOCKS : num-DIRECT_INDEX_BLOCKS;
        if (one_index > 0) {
            uint16_t *block_ids = (uint16_t *) malloc(one_index*sizeof(uint16_t));
            block_read(inode->i_block[6], block_ids, one_index*sizeof(uint16_t));
            for (int i = 0; i < one_index; ++i) {
                block_free(block_ids[i]);
            }
            free(block_ids);
        }
        /** free two index **/
        int two_index = num-DIRECT_INDEX_BLOCKS-ONE_INDEX_BLOCKS;
        if (two_index > 0) {
            int array_num = two_index / (ONE_INDEX_BLOCKS);
            int last_num = two_index % ONE_INDEX_BLOCKS;
            int read_num = array_num + ((last_num>0)?1:0);
            uint16_t *block_array = (uint16_t *)malloc(read_num*sizeof(uint16_t));
            block_read(inode->i_block[7], block_array, read_num*sizeof(uint16_t));
            for (int i = 0; i < array_num; ++i) {
                uint16_t *block_ids = (uint16_t *)malloc(BLOCK_SIZE);
                block_read(block_array[i], block_ids, BLOCK_SIZE);
                for (int j = 0; j < ONE_INDEX_BLOCKS; ++j) {
                    block_free(block_ids[j]);
                }
                free(block_ids);
            }
            if (last_num > 0) {
                uint16_t *block_ids = (uint16_t *)malloc(last_num*sizeof(uint16_t));
                block_read(block_array[array_num], block_ids, last_num*sizeof(uint16_t));
                for (int i = 0; i < last_num; ++i) {
                    block_free(block_ids[i]);
                }
                free(block_ids);
            }
            free(block_array);
        }
    } else  {
        if (inode->i_blocks <= DIRECT_INDEX_BLOCKS) {
            for (int i = 1; i <= num; ++i) {
                block_free(inode->i_block[inode->i_blocks-i]);
            }
        } else if (inode->i_blocks <= DIRECT_INDEX_BLOCKS+ONE_INDEX_BLOCKS) {
            int blocks = inode->i_blocks-DIRECT_INDEX_BLOCKS;
            uint16_t *block_ids = (uint16_t *)malloc(blocks*sizeof(uint16_t));
            block_read(inode->i_block[6], block_ids, blocks*sizeof(uint16_t));
            int free_blocks = (inode->i_blocks-num <= DIRECT_INDEX_BLOCKS) ? blocks : num;
            for (int i = 0; i < free_blocks ; ++i) {
                block_free(block_ids[blocks-i-1]);
            }
            if (free_blocks >= blocks) block_free(inode->i_block[6]);
            for (int i = 1, size = num-blocks; i <= size; ++i) {
                block_free(inode->i_block[DIRECT_INDEX_BLOCKS-i]);
                inode->i_block[DIRECT_INDEX_BLOCKS-i] = 0;
            }
            free(block_ids);
        } else if (inode->i_blocks <= TWO_INDEX_BLOCKS) {
            int two_index_blocks = inode->i_blocks-DIRECT_INDEX_BLOCKS-ONE_INDEX_BLOCKS;
            int one_index_blocks = ONE_INDEX_BLOCKS;
            int direct_index_blocks = DIRECT_INDEX_BLOCKS;
            int free_two_index_blocks = (inode->i_blocks-num <= DIRECT_INDEX_BLOCKS + ONE_INDEX_BLOCKS) ? two_index_blocks : num;
            int free_one_index_blocks = (inode->i_blocks-num <= DIRECT_INDEX_BLOCKS) ? one_index_blocks : num-free_two_index_blocks;
            int free_direct_index_blocks = num-free_two_index_blocks-free_one_index_blocks;

            if (free_two_index_blocks > 0) {
                int array_num = two_index_blocks / ONE_INDEX_BLOCKS;
                int last_num = two_index_blocks % ONE_INDEX_BLOCKS;
                int read_num = array_num + (last_num>0?1:0);
                uint16_t *block_array = (uint16_t *)malloc(read_num*sizeof(uint16_t));
                block_read(inode->i_block[7], block_array, read_num*sizeof(uint16_t));
                int free_blocks_except_last_num = free_two_index_blocks - last_num;
                int free_array_num = free_blocks_except_last_num / ONE_INDEX_BLOCKS;
                int free_last_num = free_blocks_except_last_num % ONE_INDEX_BLOCKS;
                int free_read_num = free_array_num + (free_last_num>0?1:0);

                if (last_num > 0) {
                    uint16_t *block_ids = (uint16_t *)malloc(last_num*sizeof(uint16_t));
                    block_read(block_array[array_num], block_ids, last_num*sizeof(uint16_t));
                    for (int i = 0, index = last_num-1, size = free_blocks_except_last_num<0?free_two_index_blocks:last_num; i < size; ++i, --index) {
                        block_free(block_ids[index]);
                        block_ids[index] = 0;
                    }
                    block_write(block_array[array_num], block_ids, last_num*sizeof(uint16_t));
                    free(block_ids);
                    if (free_blocks_except_last_num >= 0) block_free(block_array[array_num]);
                }
                
                if (free_array_num > 0) {
                    uint16_t *block_ids = (uint16_t *)malloc(BLOCK_SIZE*sizeof(uint16_t));                
                    for (int i = 0, index = array_num-1; i < free_array_num; ++i, --index) {
                        block_read(block_array[index], block_ids, BLOCK_SIZE*sizeof(uint16_t));
                        for (int j = 0; j < BLOCK_SIZE; ++j) {
                            block_free(block_ids[j]);
                        }
                        block_free(block_array[index]);
                        block_array[index] = 0;
                    }
                    free(block_ids);
                }

                if (free_last_num > 0) {
                    uint16_t *block_ids = (uint16_t *)malloc(BLOCK_SIZE*sizeof(uint16_t));                
                    int free_index = array_num-free_array_num-1;
                    block_read(block_array[free_index], block_ids, BLOCK_SIZE*sizeof(uint16_t));
                    for (int i = 0, index = BLOCK_SIZE-1; i < free_last_num; ++i, --index) {
                        block_free(block_ids[i]);
                        block_ids[i] = 0;
                    }
                    block_write(block_array[free_index], block_ids, BLOCK_SIZE*sizeof(uint16_t));
                    free(block_ids);
                }

                if (free_two_index_blocks == two_index_blocks) {
                    block_free(inode->i_block[7]);
                    inode->i_block[7] = 0;
                }
            }

            if (free_one_index_blocks > 0) {
                uint16_t *block_ids = (uint16_t *)malloc(one_index_blocks*sizeof(uint16_t));
                block_read(inode->i_block[6], block_ids, one_index_blocks*sizeof(uint16_t));
                for (int i = 0, index = one_index_blocks-1; i < free_one_index_blocks; ++i, --index) {
                    block_free(block_ids[index]);
                    block_ids[index] = 0;
                }
                block_write(inode->i_block[6], block_ids, one_index_blocks*sizeof(uint16_t));
                free(block_ids);
                if (free_one_index_blocks >= one_index_blocks) block_free(inode->i_block[6]);
            }

            if (free_direct_index_blocks > 0) {
                for (int i = 0, index = DIRECT_INDEX_BLOCKS-1; i < free_direct_index_blocks; ++i, --index) {
                    block_free(inode->i_block[index]);
                    inode->i_block[index] = 0;
                }
            }

            return -1;
        }
    }
    inode->i_blocks -= ((num>inode->i_blocks)?inode->i_blocks:num);
    return inode_write(inode_id, inode);
}

int inode_block_alloc(uint16_t inode_id, myext2_inode *inode, uint16_t num) {
    if (inode == NULL) return -1;
    if (inode->i_blocks+num > TWO_INDEX_BLOCKS) return -1;
    while (num--) {
        if (inode->i_blocks < DIRECT_INDEX_BLOCKS) {
            int block_id = get_empty_block();
            if (block_id < 0) return -1;
            block_alloc(block_id);
            inode->i_block[inode->i_blocks++] = block_id;
        } else if (inode->i_blocks < DIRECT_INDEX_BLOCKS+ONE_INDEX_BLOCKS) {
            int block_size = inode->i_blocks-DIRECT_INDEX_BLOCKS;
            if (inode->i_block[6] == 0) {
                int block_id = get_empty_block();
                if (block_id < 0) return -1;
                block_alloc(block_id);
                inode->i_block[6] = block_id;
            }
            int block_id = get_empty_block();
            if (block_id < 0) return -1;
            block_alloc(block_id);
            block_append(inode->i_block[6], &block_id, sizeof(uint16_t), sizeof(uint16_t)*block_size);
            ++inode->i_blocks;
        } else if (inode->i_blocks < TWO_INDEX_BLOCKS) {
            int block_size = inode->i_blocks-DIRECT_INDEX_BLOCKS-ONE_INDEX_BLOCKS;
            int array_num = block_size / ONE_INDEX_BLOCKS;
            int last_num = block_size % ONE_INDEX_BLOCKS;
            int read_num = array_num + (last_num>0?1:0);
            uint16_t *block_array = (uint16_t *)malloc((array_num+1)*sizeof(uint16_t));
            if (inode->i_block[7] == 0) {
                int block_id = get_empty_block();
                if (block_id < 0) return -1;
                block_alloc(block_id);
                inode->i_block[7] = block_id;
            } else {
                block_read(inode->i_block[7], block_array, read_num*sizeof(uint16_t));
            }
            if (last_num > 0) {
                int block_id = get_empty_block();
                if (block_id < 0) return -1;
                block_alloc(block_id);
                block_append(block_array[array_num], &block_id, sizeof(uint16_t), last_num*sizeof(uint16_t));
            } else {
                int block_array_id = get_empty_block();
                if (block_array_id < 0) return -1;
                block_alloc(block_array_id);
                block_array[array_num] = block_array_id;
                int block_id = get_empty_block();
                if (block_id < 0) return -1;
                block_alloc(block_id);
                block_write(block_array_id, &block_id, sizeof(uint16_t));
            }
            block_write(inode->i_block[7], block_array, (array_num+1)*sizeof(uint16_t));
            free(block_array);
            ++inode->i_blocks;
        } else {
            return -1;
        }
    }
    inode_write(inode_id, inode);
}

int inode_block_get_block_by_num(uint16_t inode_id, myext2_inode *inode, uint32_t block_num) {
    if (inode == NULL) return -1;
    int block_id = 0;
    if (block_num < DIRECT_INDEX_BLOCKS) {
        block_id = inode->i_block[block_num];
    } else if (block_num < DIRECT_INDEX_BLOCKS+ONE_INDEX_BLOCKS) {
        int one_index_block = block_num-DIRECT_INDEX_BLOCKS;
        uint16_t *block_ids = (uint16_t *)malloc(ONE_INDEX_BLOCKS*sizeof(uint16_t));
        block_read(inode->i_block[6], block_ids, ONE_INDEX_BLOCKS*sizeof(uint16_t));
        block_id = block_ids[one_index_block-1];
        free(block_ids);
    } else {
        int two_index_blocks = inode->i_blocks-DIRECT_INDEX_BLOCKS-ONE_INDEX_BLOCKS;
        int two_index_block = block_num-DIRECT_INDEX_BLOCKS-ONE_INDEX_BLOCKS;
        int array_num = two_index_block / ONE_INDEX_BLOCKS;
        int last_num = two_index_block % ONE_INDEX_BLOCKS;
        int read_num = array_num + (last_num>0?1:0);
        uint16_t *block_array = (uint16_t *)malloc(read_num*sizeof(uint16_t));
        block_read(inode->i_block[7], block_array, read_num*sizeof(uint16_t));
        uint16_t *block_ids = (uint16_t *)malloc(BLOCK_SIZE*sizeof(uint16_t));
        block_read(block_array[array_num-1], block_ids, BLOCK_SIZE*sizeof(uint16_t));
        block_id = block_ids[(last_num-1+ONE_INDEX_BLOCKS)%ONE_INDEX_BLOCKS];
        free(block_ids);
        free(block_array);
    }
    return block_id;
}

/** block **/

int get_empty_block() {
    int array_index = 0;
    int bit_index = 0;
    for (int i = 0; i < TWO_INDEX_BLOCKS; ++i) {
        array_index = i / 64;
        bit_index = i % 64;
        if (! (block_bitmap[array_index] & (1L << (63-bit_index)))) {
            return i;
        }
    }
    return -1;
}

int block_alloc(uint16_t block_id) {
    #ifdef DEBUG
        printf("[block_alloc] block_id = %d\n", block_id);
    #endif
    int array_index = block_id / 64;
    int bit_index = block_id % 64;
    if (block_bitmap[array_index] & (1L << (63-bit_index))) return -1;
    block_bitmap[array_index] |= (1L << (63-bit_index));
    #ifdef DEBUG
        printf("[block_alloc] array_index = %d, bit_index = %d, | = %llx\n", array_index, bit_index, (1L << (63-bit_index)));
        printf("[block_alloc] block_bitmap[array_index] = %llx\n", block_bitmap[array_index]);
    #endif
    fseek(fp, 2*BLOCK_SIZE, SEEK_SET);
    fwrite(block_bitmap, sizeof(block_bitmap), 1, fp);
    --group_desc.bg_free_blocks_count;
    fseek(fp, 0, SEEK_SET);
    fwrite(&group_desc, sizeof(group_desc), 1, fp);
    fflush(fp);
    return 0;
}

int block_free(uint16_t block_id) {
    int array_index = block_id / 64;
    int bit_index = block_id % 64;
    if (! (block_bitmap[array_index] & (1L << (63-bit_index)))) return 0;
    block_bitmap[array_index] &= (~(1L << (63-bit_index)));
    fseek(fp, 2*BLOCK_SIZE, SEEK_SET);
    fwrite(block_bitmap, sizeof(block_bitmap), 1, fp);
    ++group_desc.bg_free_blocks_count;
    fseek(fp, 0, SEEK_SET);
    fwrite(&group_desc, sizeof(group_desc), 1, fp);
    fflush(fp);
    return 0;
}

int block_append(uint16_t block_id, char *data, uint16_t data_size, uint16_t offset) {
    if (data == NULL) return -1;
    if (data_size+offset > BLOCK_SIZE) return -1;
    fseek(fp, (DATA_BEGIN_BLOCK+block_id)*BLOCK_SIZE+offset, SEEK_SET);
    fwrite(data, data_size, 1, fp);
    fflush(fp);
    return 0;
}

int block_write(uint16_t block_id, char *data, uint16_t data_size) {
    return block_append(block_id, data, data_size, 0);
}

int block_read(uint16_t block_id, char *data, uint16_t data_size) {
    if (data == NULL) return -1;
    fseek(fp, (DATA_BEGIN_BLOCK+block_id)*BLOCK_SIZE, SEEK_SET);
    fread(data, data_size, 1, fp);
    return 0;
}

int block_get_num_by_file_size(uint32_t file_size) {
    if (file_size <= 0) return -1;
    int blocks = file_size / BLOCK_SIZE;
    if (file_size % BLOCK_SIZE) ++blocks;
    return blocks;
}

/** dir **/

int is_dir(uint16_t inode_id, myext2_inode *inode, char *file_name) {
    
}

int is_current_dir(uint16_t inode_id, myext2_inode *inode, char *file_name) {
    if (file_name == NULL) return -1;
    char *s = strchr(file_name, '/');
    return (s == NULL) ? 0 : -1;
}

int dir_is_exists(uint16_t inode_id, myext2_inode *inode, char *file_name) {
    // if (inode == NULL || inode->i_mode == FILE_TYPE_FILE) return -1;
    // int file_size = inode->i_size;
    // int dirs = 
    // inode_block_read(inode_id, inode, )
}

int dir_create(uint16_t inode_id, myext2_inode *inode, char *file_name) {
    if (inode == NULL || file_name == NULL) return -1;
    int dir_size = inode->i_size / DIR_SIZE;
    #ifdef DEBUG
        printf("[dir_create] inode->i_size = %d, dir_size = %d\n", inode->i_size, dir_size);
    #endif // DEBUG
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(dir_size*sizeof(myext2_dir_entry));
    inode_block_read(inode_id, inode, dirs, inode->i_size);
    int has_deleted = -1;
    int is_exists = -1;
    for (int i = 0; i < dir_size; ++i) {
        #ifdef DEBUG
            printf("[dir_create] dirs[i]->name = %s, file_name = %s\n", dirs[i].name, file_name);
        #endif // DEBUG
        if (strcmp(dirs[i].name, file_name) == 0) {
            if (dirs[i].inode != 0) {
                printf("Can't create dir '%s', it has existed.\n");
                is_exists = i;
                break;
            } else {
                has_deleted = i;
            }
        }
    }
    
    if (is_exists < 0) {
        int new_inode_id = get_empty_inode();
        int inode_alloc_result = inode_alloc(new_inode_id);
        if (inode_alloc_result < 0) return -1;
        myext2_inode new_dir_inode;
        inode_init(&new_dir_inode);
        myext2_dir_entry new_dir_entry;
        time_t now;
        time(&now);
        new_dir_inode.i_ctime = now;
        new_dir_inode.i_atime = now;
        new_dir_inode.i_mtime = now;
        new_dir_inode.i_dtime = 0;
        new_dir_inode.i_mode = FILE_TYPE_DIR;
        new_dir_inode.i_blocks = 0;
        new_dir_inode.i_size = 0;
        inode_write(new_inode_id, &new_dir_inode);
        new_dir_entry.inode = new_inode_id;
        new_dir_entry.rec_len = DIR_SIZE;
        new_dir_entry.name_len = 1;
        new_dir_entry.file_type = FILE_TYPE_DIR;
        strcpy(new_dir_entry.name, ".");
        inode_block_write(new_inode_id, &new_dir_inode, &new_dir_entry, sizeof(new_dir_entry));
        new_dir_entry.inode = inode_id;
        new_dir_entry.name_len = 2;
        strcpy(new_dir_entry.name, "..");
        inode_block_append(new_inode_id, &new_dir_inode, &new_dir_entry, sizeof(new_dir_entry), sizeof(new_dir_entry));

        new_dir_entry.inode = new_inode_id;
        new_dir_entry.name_len = strlen(file_name);
        new_dir_entry.file_type = FILE_TYPE_DIR;
        strcpy(new_dir_entry.name, file_name);
        if (has_deleted >= 0) {
            dirs[has_deleted] = new_dir_entry;
            inode_block_write(inode_id, inode, dirs, dir_size*sizeof(myext2_dir_entry));
        } else {
            inode_block_append(inode_id, inode, &new_dir_entry, sizeof(new_dir_entry), dir_size*sizeof(myext2_dir_entry));
        }
        inode_write(inode_id, inode);
        printf("Create dir '%s' success.\n", file_name);
    }
    free(dirs);
    return 0;
}

int dir_delete(uint16_t inode_id, myext2_inode *inode, char *file_name) {
    if (inode == NULL || file_name == NULL) return -1;
    if (strcmp(file_name, ".") == 0 || strcmp(file_name, "..") == 0) {
        printf("Can't delete '%s'.\n", file_name);
        return 0;
    }
    if (inode->i_blocks == 2) return 0;
    int dir_size = inode->i_size / DIR_SIZE;
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(inode->i_size);
    inode_block_read(inode_id, inode, dirs, inode->i_size);
    int is_exists = -1;
    for (int i = 0; i < dir_size; ++i) {
        if (strcmp(dirs[i].name, file_name) == 0 && dirs[i].inode != 0) {
            is_exists = i;
            break;
        }
    }
    #ifdef DEBUG
        printf("[dir_delete] dirs[is_exists].name = %s, dirs[is_exists].file_type = %d\n", dirs[is_exists].name, dirs[is_exists].file_type);
    #endif // DEBUG
    if (is_exists > 0 && dirs[is_exists].file_type == FILE_TYPE_DIR) {
        int delete_inode_id = dirs[is_exists].inode;
        #ifdef DEBUG
            printf("[dir_delete] inode_id = %d\n", delete_inode_id);
        #endif // DEBUG
        dirs[is_exists].inode = 0;
        inode_block_write(inode_id, inode, dirs, inode->i_size);
        myext2_inode delete_inode;
        inode_read(delete_inode_id, &delete_inode);
        inode_block_free(delete_inode_id, &delete_inode, delete_inode.i_blocks);
        inode_free(delete_inode_id);
        printf("Delete dir '%s' success.\n", file_name);
    } else {
        printf("No dir named '%s'.\n", file_name);
    }
    free(dirs);
    return 0;
}

int dir_info(uint16_t inode_id, myext2_inode *inode) {
    if (inode == NULL) return -1;
    int dir_size = inode->i_size / DIR_SIZE;
    #ifdef DEBUG
        printf("[dir_info] inode->i_size = %d, dir_size = %d\n", inode->i_size, dir_size);
    #endif
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(dir_size*sizeof(myext2_dir_entry));
    inode_block_read(inode_id, inode, dirs, dir_size*sizeof(myext2_dir_entry));
    myext2_inode tmp_inode;
    printf("Type\t\tFileName\tCreateTime\t\t\tLastAccessTime\t\t\tModifyTime\n");
    char ctime_buffer[80], atime_buffer[80], mtime_buffer[80];
    for (int i = 0; i < dir_size; ++i) {
        if (dirs[i].inode != 0) {
            inode_read(dirs[i].inode, &tmp_inode);
            strftime(ctime_buffer, sizeof(ctime_buffer), "%Y-%m-%d %H:%M:%S", localtime(&tmp_inode.i_ctime));
            strftime(atime_buffer, sizeof(atime_buffer), "%Y-%m-%d %H:%M:%S", localtime(&tmp_inode.i_atime));
            strftime(mtime_buffer, sizeof(mtime_buffer), "%Y-%m-%d %H:%M:%S", localtime(&tmp_inode.i_mtime));
            printf("%s\t%s\t\t%s\t\t%s\t\t%s\n", 
                dirs[i].file_type == FILE_TYPE_DIR ? "Directory" : "File     ",
                dirs[i].name,
                ctime_buffer,
                atime_buffer,
                mtime_buffer
            );
        }
    }
    return 0;
}

int dir_child(uint16_t inode_id, myext2_inode *inode, char *file_name, myext2_inode *child) {
    if (inode == NULL || file_name == NULL) return -1;
    int dir_size = inode->i_size / DIR_SIZE;
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(inode->i_size);
    inode_block_read(inode_id, inode, dirs, inode->i_size);
    int is_exists = -1;
    for (int i = 0; i < dir_size; ++i) {
        if (strcmp(dirs[i].name, file_name) == 0 && dirs[i].inode != 0) {
            is_exists = i;
            break;
        }
    }
    if (is_exists > 0 && child != NULL) {
        inode_read(is_exists, child);
    }
    free(dirs);
    return is_exists;
}

int dir_root_create() {
    int inode_id = get_empty_inode(); // 1
    int inode_alloc_result = inode_alloc(inode_id);
    if (inode_alloc_result < 0) {
        return -1;
    }
    myext2_inode root_inode;
    inode_init(&root_inode);
    myext2_dir_entry root_dir_entry;
    time_t now;
    time(&now);
    root_inode.i_atime = now;
    root_inode.i_ctime = now;
    root_inode.i_mtime = now;
    root_inode.i_dtime = 0;
    root_inode.i_mode = FILE_TYPE_DIR;
    root_inode.i_blocks = 0;
    root_inode.i_size = 0;
    inode_write(inode_id, &root_inode);
    root_dir_entry.inode = inode_id;
    root_dir_entry.rec_len = DIR_SIZE;
    root_dir_entry.name_len = 1;
    root_dir_entry.file_type = FILE_TYPE_DIR;
    strcpy(root_dir_entry.name, ".");
    inode_block_write(inode_id, &root_inode, &root_dir_entry, sizeof(root_dir_entry));
    root_dir_entry.name_len = 2;
    strcpy(root_dir_entry.name, "..");
    inode_block_append(inode_id, &root_inode, &root_dir_entry, sizeof(root_dir_entry), sizeof(root_dir_entry));
    return 0;
}

/** file **/

int is_file(uint16_t inode_id, myext2_inode *inode, char *file_name) {

}

int file_is_exists(uint16_t inode_id, myext2_inode *inode, char *file_name) {
    
}

int file_create(uint16_t inode_id, myext2_inode *inode, char *file_name) {
    if (inode == NULL || file_name == NULL) return -1;
    int dir_size = inode->i_size / DIR_SIZE;
    #ifdef DEBUG
        printf("[file_create] inode->i_size = %d, file_name = %s, dir_size = %d\n", inode->i_size, file_name, dir_size);
    #endif
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(inode->i_size);
    inode_block_read(inode_id, inode, dirs, inode->i_size);
    int has_deleted = -1;
    int is_exists = -1;
    for (int i = 0; i < dir_size; ++i) {
        #ifdef DEBUG
            printf("[dir_create] dirs[i]->name = %s, file_name = %s\n", dirs[i].name, file_name);
        #endif // DEBUG
        if (strcmp(dirs[i].name, file_name) == 0) {
            if (dirs[i].inode != 0) {
                printf("Can't create file '%s', it has existed.\n");
                is_exists = i;
                break;
            } else {
                has_deleted = i;
            }
        }
    }
    if (is_exists < 0) {
        int new_inode_id = get_empty_inode();
        int inode_alloc_result = inode_alloc(new_inode_id);
        if (inode_alloc_result < 0) return -1;
        myext2_inode new_inode;
        inode_init(&new_inode);
        time_t now;
        myext2_dir_entry new_dir_entry;
        time(&now);
        new_inode.i_ctime = now;
        new_inode.i_atime = now;
        new_inode.i_mtime = now;
        new_inode.i_dtime = 0;
        new_inode.i_mode = FILE_TYPE_FILE;
        new_inode.i_blocks = 0;
        new_inode.i_size = 0;
        inode_write(new_inode_id, &new_inode);
        new_dir_entry.inode = new_inode_id;
        new_dir_entry.rec_len = DIR_SIZE;
        new_dir_entry.name_len = strlen(file_name);
        new_dir_entry.file_type = FILE_TYPE_FILE;
        strcpy(new_dir_entry.name, file_name);
        if (has_deleted >= 0) {
            dirs[has_deleted] = new_dir_entry;
            inode_block_write(inode_id, inode, dirs, inode->i_size);
        } else {
            inode_block_append(inode_id, inode, &new_dir_entry, DIR_SIZE, inode->i_size);
        }
        inode_write(inode_id, inode);
        printf("Create file '%s' success.\n", file_name);        
    }
    free(dirs);
    return 0;
}

int file_delete(uint16_t inode_id, myext2_inode *inode, char *file_name) {  
    if (inode == NULL || file_name == NULL) return -1;
    if (inode->i_blocks == 2) return 0;
    int dir_size = inode->i_size / DIR_SIZE;
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(inode->i_size);
    inode_block_read(inode_id, inode, dirs, inode->i_size);
    int is_exists = -1;
    for (int i = 0; i < dir_size; ++i) {
        if (strcmp(dirs[i].name, file_name) == 0 && dirs[i].inode != 0) {
            is_exists = i;
            break;
        }
    }
    #ifdef DEBUG
        printf("[file_delete] dirs[is_exists].name = %s, dirs[is_exists].file_type = %d\n", dirs[is_exists].name, dirs[is_exists].file_type);
    #endif // DEBUG
    if (is_exists > 0 && dirs[is_exists].file_type == FILE_TYPE_FILE) {
        int delete_inode_id = dirs[is_exists].inode;
        #ifdef DEBUG
            printf("[file_delete] inode_id = %d\n", delete_inode_id);
        #endif // DEBUG
        dirs[is_exists].inode = 0;
        inode_block_write(inode_id, inode, dirs, inode->i_size);
        myext2_inode delete_inode;
        inode_read(delete_inode_id, &delete_inode);
        inode_block_free(delete_inode_id, &delete_inode, delete_inode.i_blocks);
        inode_free(delete_inode_id);
        printf("Delete file '%s' success.\n", file_name);
    } else {
        printf("No file named '%s'.\n", file_name);
    }
    free(dirs);
    return 0;
}

int file_write(uint16_t inode_id, myext2_inode *inode, char *file_name, char *buff, uint32_t size) {
    if (inode == NULL || file_name == NULL || buff == NULL) return -1;
    if (inode->i_blocks == 2) return 0;
    int dir_size = inode->i_size / DIR_SIZE;
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(inode->i_size);
    inode_block_read(inode_id, inode, dirs, inode->i_size);
    int is_exists = -1;
    for (int i = 0; i < dir_size; ++i) {
        if (strcmp(dirs[i].name, file_name) == 0 && dirs[i].inode != 0) {
            is_exists = i;
            break;
        }
    }
    if (is_exists > 0 && dirs[is_exists].file_type == FILE_TYPE_FILE) {
        int write_inode_id = dirs[is_exists].inode;
        myext2_inode write_inode;
        inode_read(write_inode_id, &write_inode);
        inode_block_write(write_inode_id, &write_inode, buff, size);
        printf("Write to file '%s' success.\n", file_name);
    } else {
        printf("No file named '%s'.\n", file_name);
    }
    free(dirs);
    return 0;
}

int file_read(uint16_t inode_id, myext2_inode *inode, char *file_name, char *buff, uint32_t size) {
    if (inode == NULL || file_name == NULL || buff == NULL) return -1;
    if (inode->i_blocks == 2) return 0;
    int dir_size = inode->i_size / DIR_SIZE;
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(inode->i_size);
    inode_block_read(inode_id, inode, dirs, inode->i_size);
    int is_exists = -1;
    for (int i = 0; i < dir_size; ++i) {
        if (strcmp(dirs[i].name, file_name) == 0 && dirs[i].inode != 0) {
            is_exists = i;
            break;
        }
    }
    if (is_exists > 0 && dirs[is_exists].file_type == FILE_TYPE_FILE) {
        int read_inode_id = dirs[is_exists].inode;
        myext2_inode read_inode;
        inode_read(read_inode_id, &read_inode);
        inode_block_read(read_inode_id, &read_inode, buff, size);
    } else {
        printf("No file named '%s'.\n", file_name);
    }
    free(dirs);
    return 0;
}

int file_size(uint16_t inode_id, myext2_inode *inode, char *file_name) {
    if (inode == NULL || file_name == NULL) return -1;
    if (inode->i_blocks == 2) return 0;
    int dir_size = inode->i_size / DIR_SIZE;
    int file_size = -1;
    myext2_dir_entry *dirs = (myext2_dir_entry *)malloc(inode->i_size);
    inode_block_read(inode_id, inode, dirs, inode->i_size);
    int is_exists = -1;
    for (int i = 0; i < dir_size; ++i) {
        if (strcmp(dirs[i].name, file_name) == 0 && dirs[i].inode != 0) {
            is_exists = i;
            break;
        }
    }
    if (is_exists > 0 && dirs[is_exists].file_type == FILE_TYPE_FILE) {
        int read_inode_id = dirs[is_exists].inode;
        myext2_inode read_inode;
        inode_read(read_inode_id, &read_inode);
        file_size = read_inode.i_size;
    }
    free(dirs);
    return file_size;
}

/** path **/

/** cache **/
