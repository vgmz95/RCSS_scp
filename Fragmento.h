#ifndef FRAGMENTO_H_
#define FRAGMENTO_H_
#include <string>
#include "ServidorSsh.h"

class Fragmento {
public:
    Fragmento(std::string K, std::string C, std::vector<std::string> S, int indice);
    std::vector<std::string> getS() const;
    std::string getC() const;
    std::string getK() const;
    void recuperar(ServidorSsh, std::string, std::string);
    void distribuir(ServidorSsh, std::string, std::string);
    bool isOk() const;
    int getIndice() const;
    void borra();

    friend std::ostream& operator<<(std::ostream& os, const Fragmento& obj);


private:
    std::string K_nombre_archivo;
    std::string C_nombre_archivo;
    std::vector<std::string> S_nombre_fragmentos_ECC;
    bool ok;
    int indice;

};



#endif
