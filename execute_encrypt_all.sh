cnt=1024
cntt=1
for i in `seq 1 20`;
do
  echo "./Privacy_Manager2 -func encrypt -data a$cntt.log -ID metodos/grupo1/1.0 -M 2 -N 4"
  ./Privacy_Manager2 -func encrypt -data a$cntt.log -ID metodos/grupo1/1.0 -M 2 -N 4
  cntt=$((cntt + 1))
  
done
