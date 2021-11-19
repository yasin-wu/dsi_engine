## 介绍
Golang版本的自定义规则的敏感信息识别引擎(Detection Sensitive Information Engine)，使用了Intel的高性能正则表达式匹配库Hyperscan
## 安装
可使用Dockerfile安装Hyperscan环境
````
os:
    - linux
    - osx
addons:
    apt:
        packages:
            - libhyperscan-dev
            - libpcap-dev
            - tree
    homebrew:
        packages:
            - pkg-config
            - hyperscan
            - libpcap
            - tree
package:
go get -u github.com/flier/gohs
go get -u github.com/hyperjumptech/grule-rule-engine
go get -u github.com/yasin-wu/dsi_engine
````
推荐使用go.mod
````
require github.com/yasin-wu/dsi_engine v2.1.1
````
