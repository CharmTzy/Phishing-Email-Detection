def editDistance(S1, S2):
    n = len(S1)
    m = len(S2)

    # Initialize two lists, prev and cur, to store the previous and current rows of the DP array
    prev = [j for j in range(m + 1)]
    cur = [0 for _ in range(m + 1)]
    
    # Loop through the characters of S1 and S2
    for i in range(1, n + 1):
        cur[0] = i  # Initialize the first element of the current row
        for j in range(1, m + 1):
            # If the characters at the current positions match, no operation is needed
            if S1[i - 1] == S2[j - 1]:
                cur[j] = prev[j - 1]
            else:
                # Calculate the minimum of three choices:
                # 1. Replace the current character (diagonal move)
                # 2. Insert a character into S1 (move up)
                # 3. Delete a character from S1 (move left)
                cur[j] = 1 + min(prev[j - 1], min(prev[j], cur[j - 1]))

        prev, cur = cur, prev  # Update prev to be the current row, and cur to be the new empty row

    # The final value in prev[m] is the minimum number of operations required
    return prev[m]

def main():
    s1 = "test"
    s2 = "testing"

    # Calculate and print the minimum number of operations required
    print("The minimum number of operations required is:", editDistance(s1, s2))

if __name__ == "__main__":
    main()
