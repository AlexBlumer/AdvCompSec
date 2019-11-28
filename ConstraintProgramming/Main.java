package lab2;

import org.jacop.core.*;

import java.util.ArrayList;
import java.util.List;

import org.jacop.constraints.*;
import org.jacop.search.*;

public class Main {
    public static void main(String[] args) {
        int graph_size = 6;
        int start = 1;
        int n_dests = 1;
        int[] dest = {6};
        int n_edges = 7;
        int[] from = {1,1,2,2,3,4,4};
        int[] to = {2,3,3,4,5,5,6};
        int[] cost = {4,2,5,10,3,4,11};
        
        System.out.println("*************** Set 1 start ***************\n");
        findPath(graph_size, start, dest, from, to, cost);
        System.out.println("\n************** Set 1 complete **************\n\n\n");
        
        int[] dest2 = {5,6};
        System.out.println("*************** Set 2 start ***************\n");
        findPath(graph_size, start, dest2, from, to, cost);
        System.out.println("\n************** Set 2 complete **************\n\n\n");
        
        
        int graph_size3 = 6;
        int start3 = 1;
        int n_dests3 = 2;
        int[] dest3 = {5,6};
        int n_edges3 = 9;
        int[] from3 = {1,1,1,2,2,3,3,3,4};
        int[] to3 = {2,3,4,3,5,4,5,6,6};
        int[] cost3 = {6,1,5,5,3,5,6,4,2};
        System.out.println("*************** Set 3 start ***************\n");
        findPath(graph_size3, start3, dest3, from3, to3, cost3);
        System.out.println("\n************** Set 3 complete **************\n\n\n");
        
    }
    
    public static int[] findPath(int nodeCount, int startingNode, int[] dests, int[] from, int[] to, int[] costs) {
        List<Integer>[] possiblePredecessors = generatePossiblePredecessors(nodeCount, from, to);
        List<Integer>[] possibleEdgeCosts = generateEdgeCosts(nodeCount, from, to, costs);
        
        // TODO currently does all destinations, need to require only the required destinations
        Store store = new Store();
        IntVar[] edgeCosts = new IntVar[nodeCount];
        IntVar[] predecessors = new IntVar[nodeCount];
        IntVar[] listIndices = new IntVar[nodeCount]; // The index for the selected value from possible* for the above arrays
        IntVar[] distanceFromStart = new IntVar[nodeCount];
        BooleanVar[] connectedToStart = new BooleanVar[nodeCount];
        
        connectedToStart[n2i(startingNode)] = new BooleanVar(store, "Connected"+startingNode, 1, 1); // Starting node is always connected to the start
        distanceFromStart[n2i(startingNode)] = new IntVar(store, "stepCount"+startingNode, 0, 0);
        predecessors[n2i(startingNode)] = new IntVar(store, "predecessor"+startingNode, 0, 0);
        edgeCosts[n2i(startingNode)] = new IntVar(store, "edgeCost"+startingNode, 0, 0);
        
        // Initialize variables
        int maxCost = 0;
        for (int i = 0; i < nodeCount; i++) {
            // Preparation for starting node already performed
            if (i == n2i(startingNode)) continue;
            
            int maxEdgeCost = 0;
            int numPossibleCosts = possibleEdgeCosts[i].size();
            for(int j = 0; j < possibleEdgeCosts[i].size(); j++) {
                int currCost = possibleEdgeCosts[i].get(j);
                if (currCost > maxEdgeCost) {
                    maxEdgeCost = currCost;
                }
            }
            
            
            connectedToStart[i] = new BooleanVar(store, "Connected"+i2n(i), 0, 1);
            distanceFromStart[i] = new IntVar(store, "stepCount"+i2n(i), 0, nodeCount);
            predecessors[i] = new IntVar(store, "predecessor"+i2n(i), 0, nodeCount);
            edgeCosts[i] = new IntVar(store, "edgeCost" + i2n(i), 0, maxEdgeCost);
            listIndices[i] = new IntVar(store, "listIndex"+i2n(i), 1, numPossibleCosts);
            
            maxCost += maxEdgeCost;
        }
        
        IntVar cost = new IntVar(store, 0, maxCost);
        
        // 
        for (int i = 0; i < nodeCount; i++) {
            if (i == n2i(startingNode)) continue;
            
            int numPossibleCosts = possibleEdgeCosts[i].size();
            
            store.impose(new ElementInteger(listIndices[i], possibleEdgeCosts[i], edgeCosts[i]));
            store.impose(new ElementInteger(listIndices[i], possiblePredecessors[i], predecessors[i]));
            
            // connectedToStart[n2i(predecessor[i])] == 1 / is true <--> connectedToStart[i] == 1
            PrimitiveConstraint[] predecessorStates = new PrimitiveConstraint[numPossibleCosts - 1];
            // Start at j=1 to skip the "self-connection" that allows for unused nodes 
            for (int j = 1; j < numPossibleCosts; j++) {
                int possiblePred = possiblePredecessors[i].get(j);
                PrimitiveConstraint predIsConnected = new XeqC(connectedToStart[n2i(possiblePred)], 1);
                PrimitiveConstraint predIsSelected = new XeqC(predecessors[i], possiblePred);
                predecessorStates[j - 1] = new And(predIsSelected, predIsConnected);
                
                // No loops. The way the above constraints work by themselves allows for loops unconnected to the start
                PrimitiveConstraint predDistance = new XplusCeqZ(distanceFromStart[n2i(possiblePred)], 1, distanceFromStart[i]);
                store.impose(new IfThen(predIsSelected, predDistance));
            }
            
            // connectedToStart[n2i(predecessor[i])] == 1 / is true <--> connectedToStart[i] == 1 
            PrimitiveConstraint predecessorIsConnected = new Or(predecessorStates);
            store.impose(new Implies(connectedToStart[i], predecessorIsConnected));
        }
        
        int numDests = dests.length;
        for (int i = 0; i < numDests; i++) {
            int dest = dests[i];
            store.impose( new XeqC(connectedToStart[n2i(dest)], 1));
        }
        
        store.impose(new SumInt(edgeCosts, "==", cost));
        
        Search<IntVar> search = new DepthFirstSearch<IntVar>();
        search.setCostVar(cost);
        search.setPrintInfo(false);
        SelectChoicePoint<IntVar> select = new InputOrderSelect<IntVar>(store, predecessors, new IndomainSimpleRandom<IntVar>());
        
        long startTime = System.currentTimeMillis();
        boolean result = search.labeling(store, select);
        int totalTime = (int) (System.currentTimeMillis() - startTime);
        String output = String.format("Took %d.%03d seconds.", totalTime / 1000, totalTime % 1000);
        System.out.println(output);
        
        int[] intPredecessors;
        if (!result) {
            System.out.println("No result possible. At least one node must be unreachable.");
            return null;
        } else {
            intPredecessors = new int[nodeCount];
            
            System.out.println("Cost: " + cost.value());
            
            for (int i = 0; i < nodeCount; i++) {
                intPredecessors[i] = predecessors[i].value();
            }
            

            System.out.print("Predecessors: [" + intPredecessors[0]);
            for (int j = 1; j < nodeCount; j++) {
                System.out.print(", " + intPredecessors[j]);
            }
            System.out.println("]");
        }
        
        return intPredecessors;
    }

    private static List<Integer>[] generateEdgeCosts(int nodeCount, int[] from, int[] to, int[] cost) {
        List<Integer>[] edgeCosts = new ArrayList[nodeCount];
        for (int i = 0; i < nodeCount; i++) {
            edgeCosts[i] = new ArrayList<Integer>();
            edgeCosts[i].add(0); // Include a self-connection with cost 0, for unnecessary nodes
        }
        
        for (int i = 0; i < from.length; i++) {
            int firstNode = from[i];
            int secondNode = to[i];
            int edgeCost = cost[i];
            
            edgeCosts[n2i(firstNode)].add(edgeCost);
            edgeCosts[n2i(secondNode)].add(edgeCost);
        }
        
        return edgeCosts;
    }

    private static List<Integer>[] generatePossiblePredecessors(int nodeCount, int[] from, int[] to) {
        List<Integer>[] possiblePredecessors = new ArrayList[nodeCount];
        for (int i = 0; i < nodeCount; i++) {
            possiblePredecessors[i] = new ArrayList<Integer>();
            possiblePredecessors[i].add(0); // Include an unconnected/no predecessor state
        }
        
        for (int i = 0; i < from.length; i++) {
            int firstNode = from[i];
            int secondNode = to[i];
            
            possiblePredecessors[n2i(firstNode)].add(secondNode);
            possiblePredecessors[n2i(secondNode)].add(firstNode);
        }
        
        return possiblePredecessors;
    }
    
    // Convert node number to index
    private static int n2i(int node) {
        return node - 1;
    }
    // Convert index to node number
    private static int i2n(int index) {
        return index + 1;
    }
}
