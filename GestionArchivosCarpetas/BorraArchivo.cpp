#include <cstdlib>
#include <string>
#include <fstream>
#include <iostream>

using namespace std;

int main(int argc, char** argv) {
    if (argc != 4) {
        cerr << "Uso:" << argv[0] << " archivo carpeta servidores.txt" << endl;
        return -1;
    }

    string archivo = std::string(argv[1]);
    string carpeta = std::string(argv[2]);
    string ruta_servidores = std::string(argv[3]);
    
    ifstream archivo_servidores(ruta_servidores.c_str());
    string servidor_str;
    while (getline(archivo_servidores, servidor_str)) {
        string comando = "ssh " + servidor_str + " 'rm -rf ~/RCSS/" + carpeta + "/" + archivo + "/'";
        cout << comando << endl;
        system(comando.c_str());
    }

    return 0;
}

