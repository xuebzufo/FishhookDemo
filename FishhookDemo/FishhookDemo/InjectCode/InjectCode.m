//
//  InjectCode.m
//  FishhookDemo
//
//  Created by Sem on 2020/8/31.
//  Copyright © 2020 SEM. All rights reserved.
//

#import "InjectCode.h"
#import "fishhook.h"
#import <dlfcn.h>
#define PT_DENY_ATTACH 31
@implementation InjectCode
// 定义函数指针. 保存原来函数地址
int(*ptrace_ptr_t)(int _request,pid_t_pid,caddr_t_addr,int_data);

// 定义新的函数
int myPtrace (int _request, pid_t _pid, caddr_t _addr, int _data){
    
    if(_request != PT_DENY_ATTACH){
        return myPtrace(_request, _pid, _addr, _data);
    }
    // 如果拒绝加载, 破坏此防护
    return 0;
}
static void (*orig_NSLog)(NSString *format, ...);
void(new_NSLog)(NSString *format, ...) {
    va_list args;
    if(format) {
        va_start(args, format);
        NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
        orig_NSLog(@"%@🚌😁😄❤️!!!!", message);
        va_end(args);
    }
}
+(void)load{
    struct rebinding ptrace1; //
    ptrace1.name = "ptrace";  // 函数符号
    ptrace1.replacement = myPtrace; // 新函数地址
    ptrace1.replaced = (void *)&ptrace_ptr_t; // 原始函数地址的指针
    
    struct rebinding ptrace2; //
    ptrace2.name = "NSLog";  // 函数符号
    ptrace2.replacement = new_NSLog; // 新函数地址
    ptrace2.replaced = (void *)&orig_NSLog; // 原始函数地址的指针
    
    // 创建数组
    struct rebinding rebinds[]={ptrace1,ptrace2};
    // 重绑定
    rebind_symbols(rebinds, 2);
    
}
@end
