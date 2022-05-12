curl --fail --location --request POST '18.213.18.68:3200/compile' --form 'file=@"'$1'"' --form 'secname="'$2'"' > $1_MAT.json
if [ $? -ne 0 ]; then
    echo "-----------"
    echo "An Error occurred"
else
    echo "-----------"
    echo "Match-action table saved in $1_MAT.json"
fi
