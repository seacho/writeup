import sys
from collections import defaultdict

def main():
    input = sys.stdin.read().split()
    idx = 0
    t = int(input[idx])
    idx += 1
    for _ in range(t):
        n = int(input[idx])
        m = int(input[idx + 1])
        idx += 2
        grid = []
        for _ in range(n):
            row = list(map(int, input[idx:idx + m]))
            grid.append(row)
            idx += m
        
        # Collect all colors
        colors = set()
        for row in grid:
            for num in row:
                colors.add(num)
        
        if len(colors) == 1:
            print(0)
            continue
        
        # Determine conflict for each color
        conflict = defaultdict(bool)
        for i in range(n):
            for j in range(m):
                current = grid[i][j]
                # Check down (i+1, j)
                if i + 1 < n and grid[i+1][j] == current:
                    conflict[current] = True
                # Check right (i, j+1)
                if j + 1 < m and grid[i][j+1] == current:
                    conflict[current] = True
        
        min_steps = float('inf')
        for C in colors:
            total = 0
            for X in colors:
                if X == C:
                    continue
                if conflict[X]:
                    total += 2
                else:
                    total += 1
            if total < min_steps:
                min_steps = total
        
        print(min_steps)

if __name__ == "__main__":
    main()
