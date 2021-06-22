#!/bin/zsh
for n in {10..300..10}
do
        counter=0
        for r in {5..$((n - 1))..5}
        do
                ((counter++))
        done
        occur=$(egrep "\,[0-9]+;[0-9]+;$n;" $1 | wc -l)
        echo "$n occurs $occur times\tshould occur $counter times\tmissing $(($counter - $occur))"
done