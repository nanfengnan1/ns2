# simulation.tcl
set ns [new Simulator]

# 配置跟踪文件
set tracefile [open trace.tr w]
$ns trace-all $tracefile
set namfile [open vis.nam w]
$ns namtrace-all $namfile

# 创建50个节点
for {set i 0} {$i < 50} {incr i} {
    set node($i) [$ns node]
    $node($i) set X_ [expr rand()*1000]
    $node($i) set Y_ [expr rand()*1000]
    $node($i) random-motion 1
}

# 配置密钥管理代理
proc init_threshold_agents {} {
    global ns node
    for {set i 0} {$i < 50} {incr i} {
        set agent($i) [new Agent/ThresholdRSA]
        $ns attach-agent $node($i) $agent($i)
	$agent($i) init $i 50 26  # N=50, T=26
    }
}

# 动态节点加入
proc add_node {time} {
    global ns
    set new_node [$ns node]
    set new_agent [new Agent/ThresholdRSA]
    $ns attach-agent $new_node $new_agent
    $ns at $time "$new_agent init 50 51 26"  # 更新门限
   #触发密钥生成和签名
    $ns at 0.1 "init_threshold_agents"
    $ns at 1.0 "$agent(0) generate_rsa_modulus"
    $ns at 2.0 "$agent(0) distribute_shares"
    $ns at 5.0 "add_node 5.0"
    $ns at 10.0 "finish"
#结束仿真
proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
   close $namfile
   exec nam vis.nam &
    exit 0
}

$ns run
