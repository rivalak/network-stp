# 计算机网络STP生成树实验
> 在mininet环境下   
> stp-reference是参考程序

## USAGE
1 make    
2 运行\*.py文件生成网络拓扑结构   
3 xterm b1 b2 b3 ...   
4 分别执行make编译出的执行文件stp ```shell ./stp > b\*-output.txt ```   
5 执行```shell sudo pkill -SIGTERM stp ```   
6 执行./dump_output.sh *num* dump输出结果   
