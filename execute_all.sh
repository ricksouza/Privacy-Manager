cnt=1024
cntt=1
for i in `seq 1 19`;
do
  echo "$i"
  ./Privacy_Manager2 -func encrypt -data a$cntt.log -ID metodos/grupo1/1.0 -M 2 -N 4
  cntt=$((cntt + 1))
  
done
