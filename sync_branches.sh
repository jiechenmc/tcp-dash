
sub_branches=("BOLA" "FESTIVE" "L2A" "RB" "THROUGHPUT")

cd dash.js


for branch in "${sub_branches[@]}"; do
    echo $branch
    git switch $branch
    git merge development
    git push
done

cd ..