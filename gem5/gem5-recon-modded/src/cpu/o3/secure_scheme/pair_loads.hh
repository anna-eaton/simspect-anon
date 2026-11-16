#ifndef __PAIR_LOADS_HH__
#define __PAIR_LOADS_HH__

#define PL_SIZE 512

using Addr = unsigned long int;

class LoadPair 
{

  Addr pointer;
  int registerIdx;
  Addr load;
  bool stlForw;
  bool valid;
  int prodRevealBit;

  public:

    // constructor
    LoadPair(void){
      pointer = -1;
      registerIdx = -1;
      valid = false;
      stlForw = false;
    }

    bool isValid(){
      return valid;
    }

    bool checkSrc(int srcIdx){
      if(registerIdx == srcIdx){
        return 1;
      }
      return 0;
    }

    void setRegister(int new_reg){
      registerIdx = new_reg;
    } 

    int getRegister(){
      return registerIdx;
    }

    void setPointer(Addr point){
      pointer = point;
    }

    Addr getPointer(){
      return pointer;
    }

    void setLoad(unsigned long int seqnum){
      load = seqnum;
    }

    int getLoad(){
      return load;
    }

    void setValid(bool validate){
      valid = validate;
    }

    void setStlForw(bool signal){
      stlForw = signal;
    }

    bool isStlForw(){
      return stlForw;
    }

    void setProdRevealBit(int bit){
      registerIdx = bit;
    } 

    int getProdRevealBit(){
      return prodRevealBit;
    } 
};

#endif 

