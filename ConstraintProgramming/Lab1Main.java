package lab1;

import org.jacop.core.*;
import org.jacop.constraints.*;
import org.jacop.search.*;

public class Lab1Main {

    public static void main(String[] args) {
        // TODO Auto-generated method stub
        int n = 9;
        int[][] prefs = {{1,3}, {1,5}, {1,8},{2,5}, {2,9}, {3,4}, {3,5}, {4,1},{4,5}, {5,6}, {5,1}, {6,1}, {6,9},{7,3}, {7,8}, {8,9}, {8,7}};
        
        method1(n, prefs);
        
    }
    
    public static int[] method1(int n, int[][] prefs) {
        int prefCount = prefs.length;
        
        Store store = new Store();
        IntVar[] positions = new IntVar[n]; // the position of person (i+1)
        for (int i = 0; i < n; i++) {
            positions[i] = new IntVar(store, "pos"+i, 1, n);
        }
        BooleanVar[] satisfiedPrefs = new BooleanVar[prefCount];
        IntVar[] distances = new IntVar[prefCount];
        for (int i = 0; i < prefCount; i++) {
            satisfiedPrefs[i] = new BooleanVar(store, "pref"+i, 0, 1);
            distances[i] = new IntVar(store, "dist"+i, 1, n);
        }
        IntVar satisfyCount = new IntVar(store, "satisfyCount", 0, prefCount);
        IntVar negativeSatisfyCount  = new IntVar(store, "satisfyCount", -prefCount, 0);
        
        
        // Keep track of the number of satisfied preferences and the negative of the number
        store.impose(new Count(satisfiedPrefs, satisfyCount, 1));
        store.impose(new XplusYeqC(satisfyCount, negativeSatisfyCount, 0));
        
        store.impose(new Alldiff(positions));
        // Measure the distances between the people in a preference. Make sure pref is marked satisfied iff distance is 1
        for (int i = 0; i < prefCount; i++) {
            IntVar pref1 = positions[prefs[i][0] - 1]; // -1 to make the people match the indices
            IntVar pref2 = positions[prefs[i][1] - 1];// -1 to make the people match the indices
            store.impose(new Distance(pref1, pref2, distances[i]));
            PrimitiveConstraint isAdjacent = new XeqC(distances[i], 1); 
            store.impose(new Reified(isAdjacent, satisfiedPrefs[i]));
        }
        
        
        Search<IntVar> search = new DepthFirstSearch<IntVar>();
        search.setCostVar(negativeSatisfyCount);
        SelectChoicePoint<IntVar> select = new InputOrderSelect<IntVar>(store, positions, new IndomainMin<IntVar>());
        
        boolean result = search.labeling(store, select);
        
        int[] order = new int[n];
        if (!result) {
            System.out.println("No result possible. If this happens, the program is very wrong.");
            return null;
        } else {
            // Generate the order from positions
            for (int i = 0; i < n; i++) {
                int pos = positions[i].value();
                order[pos-1] = i + 1;
            }
            System.out.println("Satisfied preferences: " + satisfyCount.value());
            
            System.out.print("Order: {" + order[0]);
            // Generate the order from positions
            for (int i = 1; i < n; i++) {
                System.out.print(", " + order[i]);
            }
            System.out.print("}\n");
        }
        return order;
    }
    
    public static int[] method2(int n, int[][] prefs) {
        Store store = new Store();
        IntVar[] results = new IntVar[n];
        for (int i = 0; i < n; i++) {
            results[i] = new IntVar(store, "pos"+i, 1, n);
        }
        
        store.impose(new Alldiff(results));
        
        
        
        return null; // TODO return results if successful
    }

}
