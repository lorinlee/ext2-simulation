#ifndef MYEXT2
#define MYEXT2

#include <stdint.h>
#include <time.h>

#define BLOCKS 4611
#define BLOCK_SIZE 512
#define INODE_SIZE 64
#define DATA_BEGIN_BLOCK 515
#define DIR_SIZE 32
#define MYEXT2_NAME_LENGTH 15
#define DIRECT_INDEX_LIMIT 3072
#define DIRECT_INDEX_BLOCKS 6
#define ONE_INDEX_LIMIT 131072
#define ONE_INDEX_BLOCKS 256
#define TWO_INDEX_LIMIT 2097152 // 4096*512
#define TWO_INDEX_BLOCKS 4096
#define PATH "vdisk"

#define FILE_TYPE_FILE 1
#define FILE_TYPE_DIR 2

// #define DEBUG 1

typedef struct __myext2_group_desc
{
    char bg_volume_name[16];         // 卷名
    uint16_t bg_block_bitmap;        // 保存块位图的块号
    uint16_t bg_inode_bitmap;        // 保存索引节点位图的块号
    uint16_t bg_inode_table;         // 索引节点表的起始块号
    uint16_t bg_free_blocks_count;   // 本组空闲块的个数
    uint16_t bg_free_inodes_count;   // 本组索引节点个数
    uint16_t bg_used_dirs_count;     // 本组目录的个数
    char psw[16];                    // 密码
    char bg_pad[24];                 // 填充
} myext2_group_desc;

typedef struct __myext2_inode {
    time_t i_atime;                  // 访问时间
    time_t i_ctime;                  // 创建时间
    time_t i_mtime;                  // 修改时间
    time_t i_dtime;                  // 删除时间
    uint16_t i_mode;                 // 文件类型及访问权限
    uint16_t i_blocks;               // 文件的数据块个数
    uint16_t i_size;                 // 文件大小
    uint16_t i_block[8];             // 指向数据块的指针
    char i_pad[10];                  // 填充
} myext2_inode;

typedef struct __myext2_dir_entry {
    uint16_t inode;                  // 索引号
    uint16_t rec_len;                // 目录项长度
    uint16_t name_len;               // 文件夹长度
    uint16_t file_type;              // 文件类型 1文件 2目录
    char name[MYEXT2_NAME_LENGTH];   //文件名
    char dir_pad[9];                 // 填充
} myext2_dir_entry; 

typedef struct __cache_dir_entry {
    myext2_dir_entry *dir_entry;
    struct __cache_dir_entry *next;
    struct __cache_dir_entry *child;
    struct __cache_dir_entry *parent;
} cache_dir_entry;

char *commands[] = {
    "format",
    "password",
    "ls",
    "create",
    "delete",
    "cd",
    "close",
    "read",
    "write",
    "exit"
};

#define COMMAND_SIZE 10

#define COMMAND_FORMAT 0
#define COMMAND_PASSWORD 1
#define COMMAND_LS 2
#define COMMAND_CREATE 3
#define COMMAND_DELETE 4
#define COMMAND_CD 5
#define COMMAND_CLOSE 6
#define COMMAND_READ 7
#define COMMAND_WRITE 8
#define COMMAND_EXIT 9

int myext2_format();
int myext2_password();
int myext2_ls();
int myext2_create();
int myext2_delete();
int myext2_cd();
int myext2_close();
int myext2_read();
int myext2_write();
int myext2_exit();

#endif