curl --location --request POST 'localhost:3200/compile' --form 'file=@"'$1'"' --form 'secname="'$2'"' > $1.json

