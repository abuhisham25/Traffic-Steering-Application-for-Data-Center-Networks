import random
counter = 0
class Policy:
    """
    Represents a policy from the configurations file.
    Has two fields: match list, and chain list.
    """

    def __init__(self, matchList, chainList):
        self.match = matchList
        self.chain = chainList

def rename(oldname):
    
    # c  = random.randint(65,90)
    global counter
    counter += 1
    return oldname + str(counter)

def pre_parsing(filePath):
    f = open(filePath,"r")
    f2 = open("newConfigfile","w")
    line = f.readline()
    line = line.strip().replace("\n","")
    services = {}
    flag = False
    repeted_services = [] 
    while line != '':
        temp = line.split(" ")
        if temp[0].strip() == "service":
            line = line.replace("service","")
            line = line.strip()
            temp2 = line.split(" ")
            temp2[0] = temp2[0].strip()
            nfName = temp2[0]
            ipAddr = line.replace(nfName,"").strip()
            if services.get(nfName) is None:
                services[nfName] = [(nfName,ipAddr)]
                f2.write("service "+nfName+" "+ipAddr+"\n")
            else:
                repeted_services.append((nfName,ipAddr))
            
        else:
            if not flag :
                for nf in repeted_services :
                    newName = rename(nf[0])
                    while services.get(newName) is not None :
                        newName = rename(nf[0])
                    services[nf[0]].append((newName,nf[1]))
                    f2.write("service "+newName+" "+nf[1]+"\n")
                for service in services:
                    services[service].append(0)
                flag = True

            temp2 = line.split("chain")
            NFchain = temp2[1].strip()
            NFchain = NFchain.replace("[","").replace("]","").strip()
            nfs = NFchain.split(",")
            for i in range (len(nfs)):
                if len(services[nfs[i]]) != 2 :
                    nf = services[nfs[i]]
                    counter = nf [len(nf)-1]
                    ind = counter % (len(nf)-1)
                    nf [len(nf)-1] += 1
                    nfs[i] = nf[ind][0]

            f2.write(temp2[0]+" chain "+str(nfs).replace("'","")+"\n")
        line = f.readline()
    f.close()
    f2.close()




                

def parseConfigFile(filePath):
    """
    Reads the policies configuration file.
    extracts and returns the services alongside the policies from it
    """
    pre_parsing(filePath)
    f = open("newConfigfile", "r")

    services = {}
    policies = []
    vlanCounter = 2
    line = f.readline()
    line = line.strip().replace("\n","")
    while line != '':
        temp = line.split(" ")
        if temp[0].strip() == "service":
            line = line.replace("service","")
            line = line.strip()
            temp2 = line.split(" ")
            services[temp2[0].strip()]=[False,line.replace(temp2[0],"").strip(),vlanCounter]
            vlanCounter += 1
        else:
            line = line.replace("policy","").strip()
            line = line.replace("match","").strip()
            temp2 = line.split("chain")
            policyMatchList = []
            firstPart = temp2[0].strip().split(",")
            for i in firstPart:
                i = i.replace("[","").strip()
                i = i.replace("]","").strip()
                policyMatchList.append([j.strip() for j in i.split("=")])


            chain  = temp2[1].strip().replace("[","").replace("]","").strip().split(",")
            chainList = [j.strip() for j in chain]
            policyObj = Policy(policyMatchList, chainList)
            policies.append(policyObj)
        line = f.readline()
    # global VLAN_HOST,VLAN_SPECIAL
    VLAN_SPECIAL = vlanCounter + 1
    VLAN_HOST =  vlanCounter + 2 
    f.close()
    return [VLAN_SPECIAL,VLAN_HOST,services, policies]