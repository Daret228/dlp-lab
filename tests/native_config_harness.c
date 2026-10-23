#define main installed_gateway_main
#include "../native/filesystem_launcher.c"
#undef main
#include <assert.h>

int main(int argc,char **argv) {
    assert(argc==2);
    FILE *input=fopen(argv[1],"r"); assert(input);
    struct gateway_config parsed={0};
    int result=parse_config(input,&parsed); fclose(input);
    struct stat st={.st_uid=0,.st_mode=S_IFREG|0644,.st_nlink=1};
    assert(protected_metadata(&st,0));
    st.st_uid=1000; assert(!protected_metadata(&st,0));
    st.st_uid=0; st.st_mode|=0020; assert(!protected_metadata(&st,0));
    st.st_mode=S_IFLNK|0777; assert(!protected_metadata(&st,0));
    st.st_mode=S_IFREG|0644; st.st_nlink=2; assert(!protected_metadata(&st,0));
    if (result) printf("%u\n%u\n%s\n%s\n%s\n%s",parsed.uid,parsed.gid,parsed.home,parsed.project,parsed.telegram,parsed.exclusions);
    return result?0:2;
}
