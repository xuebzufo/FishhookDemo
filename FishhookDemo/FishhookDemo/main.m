//
//  main.m
//  FishhookDemo
//
//  Created by Sem on 2020/8/31.
//  Copyright © 2020 SEM. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include<dlfcn.h>
typedef int(*ptrace_ptr_t)(int _request,pid_t_pid,caddr_t_addr,int_data);

//void* dlopen(const char* pathname,intmode );

#if !defined(PT_DENY_ATTACH)

#define PT_DENY_ATTACH 31

#endif  // !defined(PT_DENY_ATTACH)

void disable_gdb() {
//    RTLD_LAZY:在dlopen返回前，对于动态库中存在的未定义的变量(如外部变量extern，也可以是函数)不执行解析，就是不解析这个变量的地址。
//
//    RTLD_NOW：与上面不同，他需要在dlopen返回前，解析出每个未定义变量的地址，如果解析不出来，在dlopen会返回NULL，错误为：
//
//    : undefined symbol: xxxx.......
//
//    RTLD_GLOBAL:它的含义是使得库中的解析的定义变量在随后的随后其它的链接库中变得可以使用。
    //dlopen加载动态库
    void* handle =dlopen(0,RTLD_GLOBAL|RTLD_NOW);
    //获取函数地址
    ptrace_ptr_t ptrace_ptr =dlsym(handle,"ptrace");
    //参数1:ptrace要做的事情
    //第二个参数指明了要操作进程的PID
    //第三个和第四个取决于第一个参数
    ptrace_ptr(PT_DENY_ATTACH,0,0,0);

    dlclose(handle);

}
int main(int argc, char * argv[]) {
    NSString * appDelegateClassName;
   
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
