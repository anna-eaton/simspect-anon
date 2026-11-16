#ifndef __NEW_VALUE_HH__
#define __NEW_VALUE_HH__

//#define NV_SIZE 12
#define NV_SIZE 16
//#define NV_SETS 512
//#define NV_SETS 4096
#define NV_SETS 32768

using Addr = unsigned long int;

class NewValue
{

  Addr invalidations[NV_SIZE];

  int replaces = 0;
  public:

    // constructor
    NewValue(void){
      int i;
      // Initialize
      for(i=0; i < NV_SIZE; i++){
        invalidations[i]=-1;
      }
    }

    void insertLoadAddr(Addr address){
      bool alreadyIn=false;
      bool emptyI=false;
      int pos=0, i;
      unsigned long int curr, next;
      for(i=0; i < NV_SIZE; i++){
        if(invalidations[i]==address){
          // update "lru"
          curr = invalidations[0];
          for(int j=0; j < i; j++){
            next = invalidations[j+1];
            invalidations[j+1] = curr;
            curr = next;
          }
          invalidations[0] = address;
          alreadyIn = true;
          break;
        }
        if(invalidations[i]==-1){
          emptyI = true;
          pos = i;
          break;
        }
      }

      if(alreadyIn){
      }
      else if(emptyI){
//        invalidations[pos] = address;
        // update "lru"
        curr = invalidations[0];
        for(i=0; i < pos; i++){
          next = invalidations[i+1];
          invalidations[i+1] = curr;
          curr = next;
        }
        invalidations[0] = address;
      }
      else{
        curr = invalidations[0];
        for(i=0; i < NV_SIZE-1; i++){
          next = invalidations[i+1];
          invalidations[i+1] = curr;
          curr = next;
        }
        invalidations[0] = address;
      }
    }

    void removeStore(Addr address){
      int i;
      for(i=0; i < NV_SIZE; i++){
        if(invalidations[i]==address){
          for(int j=i; j < NV_SIZE-1; j++){
            if(invalidations[j] == -1){
              break;
            }
            invalidations[j] = invalidations[j+1];
          }
          invalidations[NV_SIZE-1] = -1;
          break;
        }
        if(invalidations[i]==-1){
          break;
        }
      }
    }
    int isNewValue(Addr address){
      int i;
      for(i=0; i < NV_SIZE; i++){
        if(invalidations[i]==address){
          return 0;
        }
      }
      return 1;
    }
    int isNotNewValue(Addr address){
      int i;
      for(i=0; i < NV_SIZE; i++){
        if(invalidations[i]==address){
          return 1;
        }
      }
      return 0;
    }
};

#endif 

