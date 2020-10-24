
__attribute__((section(".Config"))) volatile struct {

  uint8_t channel;
  uint8_t somethingelse[512-16-1];
  uint8_t startupTuning[16];

} synthConfig = {

  .channel = 255,
  .somethingelse = {0},
  .startupTuning = {0}
};

__attribute__((section(".Patches"))) const uint8_t bPatches[128][64] = {

{0,0,8,0,64,0,32,0,64,0,31,64,64,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'E','l','e','c','t','r','i','c',' ','P','i','a','n','o',' ','1'},
{113,4,8,0,14,0,0,6,30,0,31,43,10,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','a','t','c','h',' ','1'},
{127,1,2,0,39,0,10,3,9,0,31,64,25,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'C','e','l','l','o'},
{14,5,8,0,17,0,12,0,12,7,25,127,17,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','a','t','c','h',' ','3'},
{11,5,8,0,49,0,43,6,105,1,37,127,3,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','i','t','a','r'},
{11,5,8,0,18,0,31,6,105,1,37,56,3,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'B','o','w','e','d',' ','1'},
{0,7,8,0,18,37,31,6,105,1,2,61,19,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','c','i','-','f','i',' ','1'},
{0,7,8,0,39,127,22,0,127,13,25,61,27,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','c','i','-','f','i',' ','2'},
{28,7,8,0,39,0,22,0,61,13,102,127,3,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'D','i','t','h','e','r','e','d',' ','Z','i','t','h','e','r'},
{28,1,8,0,86,102,10,0,61,8,127,127,32,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','a','t','c','h',' ','9'},
{0,3,8,0,34,0,0,0,60,8,127,64,127,64,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','a','t','c','h',' ','1','0'},
{127,2,8,0,16,0,0,0,21,0,31,92,29,22,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','o','f','t',' ','a','r','p','e','g','g','i','o','s'},
{0,2,8,0,10,0,0,0,21,1,57,92,4,22,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'L','e','a','d',' ','1'},
{0,2,28,0,19,74,28,15,127,0,13,39,2,76,69,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','c','i','-','f','i',' ','3'},
{0,2,4,0,19,74,28,15,127,0,13,38,17,76,69,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','m','o','o','t','h',' ','L','e','a','d'},
{127,6,8,0,38,0,0,0,65,13,72,88,9,33,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'L','e','a','d',' ','2'},
{29,3,16,0,4,0,127,0,23,1,82,127,13,22,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'O','r','g','a','n',' ','1'},
{127,3,16,0,4,0,127,0,23,1,13,39,15,22,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'O','r','g','a','n',' ','2'},
{0,1,28,0,41,127,28,15,127,0,13,39,2,22,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','o','f','t',' ','p','a','d'},
{72,1,4,0,12,0,16,0,51,7,13,127,17,76,69,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','a','t','c','h',' ','1','9'},
{40,0,32,0,29,18,16,0,18,1,13,50,46,76,69,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','a','t','c','h',' ','2','0'},
{0,0,32,0,22,0,7,0,18,1,40,50,41,76,69,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','a','t','c','h',' ','2','1'},
{71,3,8,0,0,0,7,21,55,12,40,127,10,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','t','r','i','n','g','s',' ','1'},
// {80,3,8,0,0,0,7,21,55,16,33,127,10,76,0}, // strings2
{56,3,40,0,10,1,127,0,55,13,127,127,4,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'B','o','t','t','l','e',' ','B','l','o','w'},
{56,3,127,0,14,4,127,0,55,3,104,127,4,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'C','r','y','s','t','a','l','s'},
{0,7,8,0,21,0,20,0,55,8,73,50,4,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'C','l','a','v','i','n','e','t'},
{0,5,8,0,14,0,7,0,54,8,73,50,4,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'B','a','s','s',' ','1'},
{0,5,8,0,65,63,7,0,54,13,95,50,4,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'H','a','r','m','o','n','i','c',' ','P','r','o','g','r','e','s','s','i','o','n'},
{0,5,8,0,127,0,19,0,54,13,115,50,4,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','i','p','e','s',' ','1'},
{0,7,8,0,127,0,19,0,54,13,127,50,4,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','i','p','e','s',' ','2'},
{22,7,8,0,52,0,7,0,65,13,72,127,9,76,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'C','a','v','e','r','n'},
{127,7,8,0,58,0,9,0,36,13,92,88,2,33,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','i','p','e','s',' ','3'},
{127,1,2,0,8,0,16,0,36,8,92,88,9,33,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'S','h','a','k','y',' ','F','i','f','t','h','s'},
{8,3,27,0,64,0,32,0,64,3,31,127,4,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'O','b','l','i','g','a','t','o','r','y',' ','B','e','l','l'},
{0,8,8,0,32,0,32,0,31,0,127,42,0,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','o','l','y',' ','s','q','u','a','r','e','s'},
{0,9,90,48,0,26,28,6,13,2,33,42,29,112,51,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'B','a','s','i','c',' ','s','u','b','t','r','a','c','t','i','v','e',' ','1'},
{0,9,90,48,0,0,28,0,13,0,127,42,35,61,38,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'B','a','s','i','c',' ','s','u','b','t','r','a','c','t','i','v','e',' ','2'},
{0,9,79,127,33,39,17,0,13,1,64,88,10,61,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'P','W','M',' ','F','i','f','t','h','s'},
{127,9,58,39,0,0,0,0,33,5,0,55,4,127,84,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'T','e','l','s','t','a','r',' ','S','a','w'},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0},
{0}
};