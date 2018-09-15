mininetIp = 192.168.58.101
all:
	cd code;\
	scp ./*.py mininet@$(mininetIp):pox/pox/samples;\
	cd ../;\
	cd others;\
	scp ./policyConfig mininet@$(mininetIp):/home/mininet

sendCode:
	cd code;\
	scp ./*.py mininet@$(mininetIp):pox/pox/samples
	
sendTopo2:
	cd topologies;\
	cd 2LevelTopo;\
	scp ./* mininet@$(mininetIp):

sendTopo3:
	cd topologies;\
	cd 3LevelTopo;\
	scp ./* mininet@$(mininetIp):

sendPolicy:
	cd others;\
	scp ./policyConfig mininet@$(mininetIp):/home/mininet


