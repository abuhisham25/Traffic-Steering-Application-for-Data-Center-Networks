# Traffic-Steering-Application-for-Data-Center-Networks #
The use of middleboxes in networks became an elementary need, especially when it comes to datacenter networks. However, designing Networks that support and make use of middleboxes is not an easy task. Fortunately, Software Defined Networking (SDN) provides a bunch of astonishing chances and alternatives for such implementations, but also has its own challenges.  

In this project, we aim to utilize the capabilities offered by the use of SDN in order to implement an advanced Traffic Steering Application (TSA) for datacenter networks. Our implementation targets a specific type of networks called Folded Clos Networks (or Fat Trees). A Clos Network is a multistage switching network first formalized by Charles Clos in 1953, and was used for building telecommunication networks. A Folded Clos Network (or Fat Tree) is a special type of Clos Networks where the topology of such a network takes the shape of a tree (may vary in number of levels) where links closer to the root intend to have higher bandwidth than those closer to the leaves of the tree. It was invented by Charles Leiserson in 1985, and since then, it has been widely used as a reference topology for datacenter networks.  

Building the project required the use of the following:  
1)	Mininet – provided the capability of demonstrating the Network virtually.  
See http://mininet.org/ for more on Mininet.  
2)	Openflow POX – SDN Controller written in Python.  
See https://openflow.stanford.edu/display/ONL/POX+Wiki for more on the POX controller.  
3)	Click – provided the capability to create the middleboxes for the Network as click elements, and implement the NFs.  
See http://read.cs.ucla.edu/click/click for more on Click.  

Our implementation supports a Topology with several Network Functions (NFs) and policy chains that require matching packets to go through the specified NFs within the datacenter network before reaching its destination. We do so by accepting a configuration file that contains a list of policies (matching fields to check for using POX Match structure), and the corresponding NFs that matching packets should be directed through. (See “policyConfig” file for an example of the format)  

Supported NFs are any Click elements implemented to act as a Virtual NFs.

See Traffic Steering Application for Data Center Networks.pdf for implementation and execution details.

## 2-Level fat tree topology used for testing ##
![2LevelFatTree](https://github.com/abuhisham25/Traffic-Steering-Application-for-Data-Center-Networks/blob/master/Topologies%20Diagrams/2LevelFatTree.png)

## 3-Level fat tree topology used for testing ##
![3LevelFatTree](https://github.com/abuhisham25/Traffic-Steering-Application-for-Data-Center-Networks/blob/master/Topologies%20Diagrams/3LevelFatTree.png)

# Contact #
For more details about me, please see [my LinkedIn page](https://www.linkedin.com/in/abuhisham/)
