
#!/bin/bash
echo "PATTERN PATTERN" >> example_file.txt
echo "PATTERN" >> example_file.txt
grep -c "PATTERN" example_file.txt | grep -q "[0-9]\+ [>] 2" && echo "More than two matches found!" || (
    # If not, check if there are exactly two matches
    grep -c "PATTERN" example_file.txt | grep -q "^[0-9]+$" && echo "Exactly two matches found." || echo "Less than two matches found."
)
