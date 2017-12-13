#include "Fragmento.h"
#include "ezpwd/rs"
#include "ServidorSsh.h"

Fragmento::Fragmento(std::string K, std::string C, std::vector<std::string> S, int indice) {
    this->K_nombre_archivo = K;
    this->C_nombre_archivo = C;
    this->S_nombre_fragmentos_ECC = S;
    this->ok = false;
    this->indice = indice;
}

void Fragmento::borra() {
    std::remove(K_nombre_archivo.c_str());
    std::remove(C_nombre_archivo.c_str());
    for (auto &s : S_nombre_fragmentos_ECC) {
        std::remove(s.c_str());
    }
}

void Fragmento::distribuir(ServidorSsh servidor, std::string carpeta, std::string nombre_archivo) {
    std::vector <std::string> archivos;
    archivos.reserve(K_nombre_archivo.size() + C_nombre_archivo.size() + S_nombre_fragmentos_ECC.size());
    archivos.push_back(K_nombre_archivo);
    archivos.push_back(C_nombre_archivo);
    archivos.insert(archivos.end(), S_nombre_fragmentos_ECC.begin(), S_nombre_fragmentos_ECC.end());
    ok = servidor.copiaHome(archivos, carpeta, nombre_archivo);
}

void Fragmento::recuperar(ServidorSsh servidor, std::string carpeta, std::string nombre_archivo) {
    std::vector <std::string> archivos;
    archivos.reserve(K_nombre_archivo.size() + C_nombre_archivo.size() + S_nombre_fragmentos_ECC.size());
    archivos.push_back(K_nombre_archivo);
    archivos.push_back(C_nombre_archivo);
    archivos.insert(archivos.end(), S_nombre_fragmentos_ECC.begin(), S_nombre_fragmentos_ECC.end());
    ok = servidor.recuperaHome(archivos, carpeta, nombre_archivo);
}

std::ostream& operator<<(std::ostream& os, const Fragmento& obj) {
    // Write obj to stream
    os << "Fragmento número " << obj.indice << std::endl;
    os << "K:" << obj.K_nombre_archivo << ",\nC:" << obj.C_nombre_archivo << ",\nS: {" << std::endl;
    for (auto const& s : obj.S_nombre_fragmentos_ECC) {
        os << s << "," << std::endl;
    }
    os << "}" << std::endl;
    return os;
}

std::vector<std::string> Fragmento::getS() const {
    return S_nombre_fragmentos_ECC;
}

std::string Fragmento::getC() const {
    return C_nombre_archivo;
}

std::string Fragmento::getK() const {
    return K_nombre_archivo;
}

bool Fragmento::isOk() const {
    return ok;
}

int Fragmento::getIndice() const {
    return indice;
}
