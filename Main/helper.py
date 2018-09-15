class RulesTable:
    """
    Represents the table of all rules installed on the switches
    of the network. Used in order to get a clear image of the 
    behavior of the switches, and to see what rules are
    installed on each switch.
    """

    rules = {}
    class Rule:
        """
        Represents a single rule installed on a switch in the network.
        """

        def __init__(self,mList,vlan,outputPort,inPort=None,newVlan=None):
            self.mList = mList
            self.vlan = vlan
            self.inPort = inPort
            self.outputPort = outputPort
            self.newVlan = newVlan

        def __str__(self):
            result = "matchList is "+str(self.mList)
            result+="\n"
            if self.vlan!="null":
                result =result+"VLAN = "+str(self.vlan)
            if self.inPort !=None:
                result=result+"\ninPort = "+str(self.inPort)
            result+="\n---------------action---------"
            result+="\noutput port = "+str(self.outputPort)
            if self.newVlan != None:
                result = result+"\nchange vlan to newVlan = "+str(self.newVlan)
            return result+"\n---------------end action---------\n\n"

    
    @staticmethod
    def addRule(switch,mList,vlan,outputPort,inPort=None,newVlan=None):
        """
        adds a rule to the RulesTable of the given switch
        """

        r = RulesTable.Rule(mList,vlan,outputPort,inPort,newVlan)
        ind=RulesTable.rules.get(int(switch))
        if(ind ==None):
            RulesTable.rules[int(switch)]=[r]
        else:
            ind.append(r)

    def __str__(self):
        result = "\n\n****************************************** Rules Report ******************************************\n"
        for s in RulesTable.rules:
            result+="\n$$$$$$$$$$$$$$$$$$$ Switch rules s = "+str(s)+" $$$$$$$$$$$$$$$$$$$\n\n"
            for rule in RulesTable.rules[s]:
                result +=str(rule)
            result+="\n$$$$$$$$$$$$$$$$$$$ End switch rules $$$$$$$$$$$$$$$$$$$\n"
        RulesTable.rules = {}
        return result+"\n****************************************** end Rules Report ******************************************\n"




def compute_Subnet(address, mask):
    """
    Given an IP address and a mask, this function computes and returns
    the subnet of this address in dotted string notation.
    """

    binaryMask = ""
    for i in range(32):
        if i < int(mask):
            binaryMask += "1"
        else:
            binaryMask += "0"

    binaryIP = "".join(format(int(x), '08b') for x in address.split('.'))
    intIP = int(binaryIP, 2)
    intMask = int(binaryMask, 2)
    intPrefix = intIP & intMask
    binaryPrefix = format(intPrefix, '032b')

    i = 0
    subnet = ""
    while i < 4:
        temp = binaryPrefix[i*8:(i*8)+8]
        temp = str(int(temp, 2))
        temp += '.'
        subnet += temp
        i += 1

    return subnet[:len(subnet)-1]