all: Share Recover
	
Share: Archivo.cpp Hash.cpp ServidorSsh.cpp Share.cpp
	g++ -std=c++0x -g3 -Wall -Wextra -Wno-unused "Share.cpp" "Llave.cpp" "Archivo.cpp" "Hash.cpp" "Fragmento.cpp" "ServidorSsh.cpp" -o "Share" -lcryptopp
	
Recover: Archivo.cpp Hash.cpp ServidorSsh.cpp Recover.cpp 
	g++ -std=c++0x -g3 -Wall -Wextra -Wno-unused "Recover.cpp" "Llave.cpp" "Archivo.cpp" "Hash.cpp" "Fragmento.cpp" "ServidorSsh.cpp" -o "Recover" -lcryptopp

clean:
	rm Recover Share

# "encrypt_input_files = "+ruta_servidores+", "+ruta_y_nombre+"\n"\
