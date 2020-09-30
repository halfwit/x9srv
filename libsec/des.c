#include <u.h>
#include <libc.h>
#include "../include/libsec.h"

/*
 * integrated sbox & p perm
 */
static u32int spbox[] = {

0x00808200,0x00000000,0x00008000,0x00808202,0x00808002,0x00008202,0x00000002,0x00008000,
0x00000200,0x00808200,0x00808202,0x00000200,0x00800202,0x00808002,0x00800000,0x00000002,
0x00000202,0x00800200,0x00800200,0x00008200,0x00008200,0x00808000,0x00808000,0x00800202,
0x00008002,0x00800002,0x00800002,0x00008002,0x00000000,0x00000202,0x00008202,0x00800000,
0x00008000,0x00808202,0x00000002,0x00808000,0x00808200,0x00800000,0x00800000,0x00000200,
0x00808002,0x00008000,0x00008200,0x00800002,0x00000200,0x00000002,0x00800202,0x00008202,
0x00808202,0x00008002,0x00808000,0x00800202,0x00800002,0x00000202,0x00008202,0x00808200,
0x00000202,0x00800200,0x00800200,0x00000000,0x00008002,0x00008200,0x00000000,0x00808002,

0x40084010,0x40004000,0x00004000,0x00084010,0x00080000,0x00000010,0x40080010,0x40004010,
0x40000010,0x40084010,0x40084000,0x40000000,0x40004000,0x00080000,0x00000010,0x40080010,
0x00084000,0x00080010,0x40004010,0x00000000,0x40000000,0x00004000,0x00084010,0x40080000,
0x00080010,0x40000010,0x00000000,0x00084000,0x00004010,0x40084000,0x40080000,0x00004010,
0x00000000,0x00084010,0x40080010,0x00080000,0x40004010,0x40080000,0x40084000,0x00004000,
0x40080000,0x40004000,0x00000010,0x40084010,0x00084010,0x00000010,0x00004000,0x40000000,
0x00004010,0x40084000,0x00080000,0x40000010,0x00080010,0x40004010,0x40000010,0x00080010,
0x00084000,0x00000000,0x40004000,0x00004010,0x40000000,0x40080010,0x40084010,0x00084000,

0x00000104,0x04010100,0x00000000,0x04010004,0x04000100,0x00000000,0x00010104,0x04000100,
0x00010004,0x04000004,0x04000004,0x00010000,0x04010104,0x00010004,0x04010000,0x00000104,
0x04000000,0x00000004,0x04010100,0x00000100,0x00010100,0x04010000,0x04010004,0x00010104,
0x04000104,0x00010100,0x00010000,0x04000104,0x00000004,0x04010104,0x00000100,0x04000000,
0x04010100,0x04000000,0x00010004,0x00000104,0x00010000,0x04010100,0x04000100,0x00000000,
0x00000100,0x00010004,0x04010104,0x04000100,0x04000004,0x00000100,0x00000000,0x04010004,
0x04000104,0x00010000,0x04000000,0x04010104,0x00000004,0x00010104,0x00010100,0x04000004,
0x04010000,0x04000104,0x00000104,0x04010000,0x00010104,0x00000004,0x04010004,0x00010100,

0x80401000,0x80001040,0x80001040,0x00000040,0x00401040,0x80400040,0x80400000,0x80001000,
0x00000000,0x00401000,0x00401000,0x80401040,0x80000040,0x00000000,0x00400040,0x80400000,
0x80000000,0x00001000,0x00400000,0x80401000,0x00000040,0x00400000,0x80001000,0x00001040,
0x80400040,0x80000000,0x00001040,0x00400040,0x00001000,0x00401040,0x80401040,0x80000040,
0x00400040,0x80400000,0x00401000,0x80401040,0x80000040,0x00000000,0x00000000,0x00401000,
0x00001040,0x00400040,0x80400040,0x80000000,0x80401000,0x80001040,0x80001040,0x00000040,
0x80401040,0x80000040,0x80000000,0x00001000,0x80400000,0x80001000,0x00401040,0x80400040,
0x80001000,0x00001040,0x00400000,0x80401000,0x00000040,0x00400000,0x00001000,0x00401040,

0x00000080,0x01040080,0x01040000,0x21000080,0x00040000,0x00000080,0x20000000,0x01040000,
0x20040080,0x00040000,0x01000080,0x20040080,0x21000080,0x21040000,0x00040080,0x20000000,
0x01000000,0x20040000,0x20040000,0x00000000,0x20000080,0x21040080,0x21040080,0x01000080,
0x21040000,0x20000080,0x00000000,0x21000000,0x01040080,0x01000000,0x21000000,0x00040080,
0x00040000,0x21000080,0x00000080,0x01000000,0x20000000,0x01040000,0x21000080,0x20040080,
0x01000080,0x20000000,0x21040000,0x01040080,0x20040080,0x00000080,0x01000000,0x21040000,
0x21040080,0x00040080,0x21000000,0x21040080,0x01040000,0x00000000,0x20040000,0x21000000,
0x00040080,0x01000080,0x20000080,0x00040000,0x00000000,0x20040000,0x01040080,0x20000080,

0x10000008,0x10200000,0x00002000,0x10202008,0x10200000,0x00000008,0x10202008,0x00200000,
0x10002000,0x00202008,0x00200000,0x10000008,0x00200008,0x10002000,0x10000000,0x00002008,
0x00000000,0x00200008,0x10002008,0x00002000,0x00202000,0x10002008,0x00000008,0x10200008,
0x10200008,0x00000000,0x00202008,0x10202000,0x00002008,0x00202000,0x10202000,0x10000000,
0x10002000,0x00000008,0x10200008,0x00202000,0x10202008,0x00200000,0x00002008,0x10000008,
0x00200000,0x10002000,0x10000000,0x00002008,0x10000008,0x10202008,0x00202000,0x10200000,
0x00202008,0x10202000,0x00000000,0x10200008,0x00000008,0x00002000,0x10200000,0x00202008,
0x00002000,0x00200008,0x10002008,0x00000000,0x10202000,0x10000000,0x00200008,0x10002008,

0x00100000,0x02100001,0x02000401,0x00000000,0x00000400,0x02000401,0x00100401,0x02100400,
0x02100401,0x00100000,0x00000000,0x02000001,0x00000001,0x02000000,0x02100001,0x00000401,
0x02000400,0x00100401,0x00100001,0x02000400,0x02000001,0x02100000,0x02100400,0x00100001,
0x02100000,0x00000400,0x00000401,0x02100401,0x00100400,0x00000001,0x02000000,0x00100400,
0x02000000,0x00100400,0x00100000,0x02000401,0x02000401,0x02100001,0x02100001,0x00000001,
0x00100001,0x02000000,0x02000400,0x00100000,0x02100400,0x00000401,0x00100401,0x02100400,
0x00000401,0x02000001,0x02100401,0x02100000,0x00100400,0x00000000,0x00000001,0x02100401,
0x00000000,0x00100401,0x02100000,0x00000400,0x02000001,0x02000400,0x00000400,0x00100001,

0x08000820,0x00000800,0x00020000,0x08020820,0x08000000,0x08000820,0x00000020,0x08000000,
0x00020020,0x08020000,0x08020820,0x00020800,0x08020800,0x00020820,0x00000800,0x00000020,
0x08020000,0x08000020,0x08000800,0x00000820,0x00020800,0x00020020,0x08020020,0x08020800,
0x00000820,0x00000000,0x00000000,0x08020020,0x08000020,0x08000800,0x00020820,0x00020000,
0x00020820,0x00020000,0x08020800,0x00000800,0x00000020,0x08020020,0x00000800,0x00020820,
0x08000800,0x00000020,0x08000020,0x08020000,0x08020020,0x08000000,0x00020000,0x08000820,
0x00000000,0x08020820,0x00020020,0x08000020,0x08020000,0x08000800,0x08000820,0x00000000,
0x08020820,0x00020800,0x00020800,0x00000820,0x00000820,0x00020020,0x08000000,0x08020800,
};

/*
 * for manual index calculation
 * #define fetch(box, i, sh) (*((u32int*)((uchar*)spbox + (box << 8) + ((i >> (sh)) & 0xfc))))
 */
#define fetch(box, i, sh) ((spbox+(box << 6))[((i >> (sh + 2)) & 0x3f)])

/*
 * DES electronic codebook encryption of one block
 */
void
block_cipher(ulong key[32], uchar text[8], int decrypting)
{
	u32int right, left, v0, v1;
	int i, keystep;

	/*
	 * initial permutation
	 */
	v0 = text[0] | ((u32int)text[2]<<8) | ((u32int)text[4]<<16) | ((u32int)text[6]<<24);
	left = text[1] | ((u32int)text[3]<<8) | ((u32int)text[5]<<16) | ((u32int)text[7]<<24);
	right = (left & 0xaaaaaaaa) | ((v0 >> 1) & 0x55555555);
	left = ((left << 1) & 0xaaaaaaaa) | (v0 & 0x55555555);
	left = ((left << 6) & 0x33003300)
		| (left & 0xcc33cc33)
		| ((left >> 6) & 0x00cc00cc);
	left = ((left << 12) & 0x0f0f0000)
		| (left & 0xf0f00f0f)
		| ((left >> 12) & 0x0000f0f0);
	right = ((right << 6) & 0x33003300)
		| (right & 0xcc33cc33)
		| ((right >> 6) & 0x00cc00cc);
	right = ((right << 12) & 0x0f0f0000)
		| (right & 0xf0f00f0f)
		| ((right >> 12) & 0x0000f0f0);

	if (decrypting) {
		keystep = -2;
		key = key + 32 - 2;
	} else
		keystep = 2;
	for (i = 0; i < 8; i++) {
		v0 = key[0];
		v0 ^= (right >> 1) | (right << 31);
		left ^= fetch(0, v0, 24)
			^ fetch(2, v0, 16)
			^ fetch(4, v0, 8)
			^ fetch(6, v0, 0);
		v1 = key[1];
		v1 ^= (right << 3) | (right >> 29);
		left ^= fetch(1, v1, 24)
			^ fetch(3, v1, 16)
			^ fetch(5, v1, 8)
			^ fetch(7, v1, 0);
		key += keystep;
		
		v0 = key[0];
		v0 ^= (left >> 1) | (left << 31);
		right ^= fetch(0, v0, 24)
			^ fetch(2, v0, 16)
			^ fetch(4, v0, 8)
			^ fetch(6, v0, 0);
		v1 = key[1];
		v1 ^= (left << 3) | (left >> 29);
		right ^= fetch(1, v1, 24)
			^ fetch(3, v1, 16)
			^ fetch(5, v1, 8)
			^ fetch(7, v1, 0);
		key += keystep;
	}

	/*
	 * final permutation, inverse initial permutation
	 */
	v0 = ((left << 1) & 0xaaaaaaaa) | (right & 0x55555555);
	v1 = (left & 0xaaaaaaaa) | ((right >> 1) & 0x55555555);
	v1 = ((v1 << 6) & 0x33003300)
		| (v1 & 0xcc33cc33)
		| ((v1 >> 6) & 0x00cc00cc);
	v1 = ((v1 << 12) & 0x0f0f0000)
		| (v1 & 0xf0f00f0f)
		| ((v1 >> 12) & 0x0000f0f0);
	v0 = ((v0 << 6) & 0x33003300)
		| (v0 & 0xcc33cc33)
		| ((v0 >> 6) & 0x00cc00cc);
	v0 = ((v0 << 12) & 0x0f0f0000)
		| (v0 & 0xf0f00f0f)
		| ((v0 >> 12) & 0x0000f0f0);
	text[0] = v0;
	text[2] = v0 >> 8;
	text[4] = v0 >> 16;
	text[6] = v0 >> 24;
	text[1] = v1;
	text[3] = v1 >> 8;
	text[5] = v1 >> 16;
	text[7] = v1 >> 24;
}

/*
 * triple DES electronic codebook encryption of one block
 */
void
triple_block_cipher(ulong expanded_key[3][32], uchar text[8], int ende)
{
	ulong *key;
	u32int right, left, v0, v1;
	int i, j, keystep;

	/*
	 * initial permutation
	 */
	v0 = text[0] | ((u32int)text[2]<<8) | ((u32int)text[4]<<16) | ((u32int)text[6]<<24);
	left = text[1] | ((u32int)text[3]<<8) | ((u32int)text[5]<<16) | ((u32int)text[7]<<24);
	right = (left & 0xaaaaaaaa) | ((v0 >> 1) & 0x55555555);
	left = ((left << 1) & 0xaaaaaaaa) | (v0 & 0x55555555);
	left = ((left << 6) & 0x33003300)
		| (left & 0xcc33cc33)
		| ((left >> 6) & 0x00cc00cc);
	left = ((left << 12) & 0x0f0f0000)
		| (left & 0xf0f00f0f)
		| ((left >> 12) & 0x0000f0f0);
	right = ((right << 6) & 0x33003300)
		| (right & 0xcc33cc33)
		| ((right >> 6) & 0x00cc00cc);
	right = ((right << 12) & 0x0f0f0000)
		| (right & 0xf0f00f0f)
		| ((right >> 12) & 0x0000f0f0);

	for(j = 0; j < 3; j++){
		if((ende & 1) == DES3D) {
			key = &expanded_key[2-j][32-2];
			keystep = -2;
		} else {
			key = &expanded_key[j][0];
			keystep = 2;
		}
		ende >>= 1;
		for (i = 0; i < 8; i++) {
			v0 = key[0];
			v0 ^= (right >> 1) | (right << 31);
			left ^= fetch(0, v0, 24)
				^ fetch(2, v0, 16)
				^ fetch(4, v0, 8)
				^ fetch(6, v0, 0);
			v1 = key[1];
			v1 ^= (right << 3) | (right >> 29);
			left ^= fetch(1, v1, 24)
				^ fetch(3, v1, 16)
				^ fetch(5, v1, 8)
				^ fetch(7, v1, 0);
			key += keystep;
			
			v0 = key[0];
			v0 ^= (left >> 1) | (left << 31);
			right ^= fetch(0, v0, 24)
				^ fetch(2, v0, 16)
				^ fetch(4, v0, 8)
				^ fetch(6, v0, 0);
			v1 = key[1];
			v1 ^= (left << 3) | (left >> 29);
			right ^= fetch(1, v1, 24)
				^ fetch(3, v1, 16)
				^ fetch(5, v1, 8)
				^ fetch(7, v1, 0);
			key += keystep;
		}

		v0 = left;
		left = right;
		right = v0;
	}

	/*
	 * final permutation, inverse initial permutation
	 * left and right are swapped here
	 */
	v0 = ((right << 1) & 0xaaaaaaaa) | (left & 0x55555555);
	v1 = (right & 0xaaaaaaaa) | ((left >> 1) & 0x55555555);
	v1 = ((v1 << 6) & 0x33003300)
		| (v1 & 0xcc33cc33)
		| ((v1 >> 6) & 0x00cc00cc);
	v1 = ((v1 << 12) & 0x0f0f0000)
		| (v1 & 0xf0f00f0f)
		| ((v1 >> 12) & 0x0000f0f0);
	v0 = ((v0 << 6) & 0x33003300)
		| (v0 & 0xcc33cc33)
		| ((v0 >> 6) & 0x00cc00cc);
	v0 = ((v0 << 12) & 0x0f0f0000)
		| (v0 & 0xf0f00f0f)
		| ((v0 >> 12) & 0x0000f0f0);
	text[0] = v0;
	text[2] = v0 >> 8;
	text[4] = v0 >> 16;
	text[6] = v0 >> 24;
	text[1] = v1;
	text[3] = v1 >> 8;
	text[5] = v1 >> 16;
	text[7] = v1 >> 24;
}

/*
 * key compression permutation, 4 bits at a time
 */
static u32int comptab[] = {

0x000000,0x010000,0x000008,0x010008,0x000080,0x010080,0x000088,0x010088,
0x000000,0x010000,0x000008,0x010008,0x000080,0x010080,0x000088,0x010088,

0x000000,0x100000,0x000800,0x100800,0x000000,0x100000,0x000800,0x100800,
0x002000,0x102000,0x002800,0x102800,0x002000,0x102000,0x002800,0x102800,

0x000000,0x000004,0x000400,0x000404,0x000000,0x000004,0x000400,0x000404,
0x400000,0x400004,0x400400,0x400404,0x400000,0x400004,0x400400,0x400404,

0x000000,0x000020,0x008000,0x008020,0x800000,0x800020,0x808000,0x808020,
0x000002,0x000022,0x008002,0x008022,0x800002,0x800022,0x808002,0x808022,

0x000000,0x000200,0x200000,0x200200,0x001000,0x001200,0x201000,0x201200,
0x000000,0x000200,0x200000,0x200200,0x001000,0x001200,0x201000,0x201200,

0x000000,0x000040,0x000010,0x000050,0x004000,0x004040,0x004010,0x004050,
0x040000,0x040040,0x040010,0x040050,0x044000,0x044040,0x044010,0x044050,

0x000000,0x000100,0x020000,0x020100,0x000001,0x000101,0x020001,0x020101,
0x080000,0x080100,0x0a0000,0x0a0100,0x080001,0x080101,0x0a0001,0x0a0101,

0x000000,0x000100,0x040000,0x040100,0x000000,0x000100,0x040000,0x040100,
0x000040,0x000140,0x040040,0x040140,0x000040,0x000140,0x040040,0x040140,

0x000000,0x400000,0x008000,0x408000,0x000008,0x400008,0x008008,0x408008,
0x000400,0x400400,0x008400,0x408400,0x000408,0x400408,0x008408,0x408408,

0x000000,0x001000,0x080000,0x081000,0x000020,0x001020,0x080020,0x081020,
0x004000,0x005000,0x084000,0x085000,0x004020,0x005020,0x084020,0x085020,

0x000000,0x000800,0x000000,0x000800,0x000010,0x000810,0x000010,0x000810,
0x800000,0x800800,0x800000,0x800800,0x800010,0x800810,0x800010,0x800810,

0x000000,0x010000,0x000200,0x010200,0x000000,0x010000,0x000200,0x010200,
0x100000,0x110000,0x100200,0x110200,0x100000,0x110000,0x100200,0x110200,

0x000000,0x000004,0x000000,0x000004,0x000080,0x000084,0x000080,0x000084,
0x002000,0x002004,0x002000,0x002004,0x002080,0x002084,0x002080,0x002084,

0x000000,0x000001,0x200000,0x200001,0x020000,0x020001,0x220000,0x220001,
0x000002,0x000003,0x200002,0x200003,0x020002,0x020003,0x220002,0x220003,
};

static int keysh[] =
{
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

static void
keycompperm(u32int left, u32int right, ulong *ek)
{
	u32int v0, v1;
	int i;

	for(i = 0; i < 16; i++){
		left = (left << keysh[i]) | (left >> (28 - keysh[i]));
		left &= 0xfffffff0;
		right = (right << keysh[i]) | (right >> (28 - keysh[i]));
		right &= 0xfffffff0;
		v0 = comptab[6 * (1 << 4) + ((left >> (32-4)) & 0xf)]
			| comptab[5 * (1 << 4) + ((left >> (32-8)) & 0xf)]
			| comptab[4 * (1 << 4) + ((left >> (32-12)) & 0xf)]
			| comptab[3 * (1 << 4) + ((left >> (32-16)) & 0xf)]
			| comptab[2 * (1 << 4) + ((left >> (32-20)) & 0xf)]
			| comptab[1 * (1 << 4) + ((left >> (32-24)) & 0xf)]
			| comptab[0 * (1 << 4) + ((left >> (32-28)) & 0xf)];
		v1 = comptab[13 * (1 << 4) + ((right >> (32-4)) & 0xf)]
			| comptab[12 * (1 << 4) + ((right >> (32-8)) & 0xf)]
			| comptab[11 * (1 << 4) + ((right >> (32-12)) & 0xf)]
			| comptab[10 * (1 << 4) + ((right >> (32-16)) & 0xf)]
			| comptab[9 * (1 << 4) + ((right >> (32-20)) & 0xf)]
			| comptab[8 * (1 << 4) + ((right >> (32-24)) & 0xf)]
			| comptab[7 * (1 << 4) + ((right >> (32-28)) & 0xf)];
		ek[0] = (((v0 >> (24-6)) & 0x3f) << 26)
			| (((v0 >> (24-18)) & 0x3f) << 18)
			| (((v1 >> (24-6)) & 0x3f) << 10)
			| (((v1 >> (24-18)) & 0x3f) << 2);
		ek[1] = (((v0 >> (24-12)) & 0x3f) << 26)
			| (((v0 >> (24-24)) & 0x3f) << 18)
			| (((v1 >> (24-12)) & 0x3f) << 10)
			| (((v1 >> (24-24)) & 0x3f) << 2);
		ek += 2;
	}
}

void
des_key_setup(uchar key[8], ulong *ek)
{
	u32int left, right, v0, v1;

	v0 = key[0] | ((u32int)key[2] << 8) | ((u32int)key[4] << 16) | ((u32int)key[6] << 24);
	v1 = key[1] | ((u32int)key[3] << 8) | ((u32int)key[5] << 16) | ((u32int)key[7] << 24);
	left = ((v0 >> 1) & 0x40404040)
		| ((v0 >> 2) & 0x10101010)
		| ((v0 >> 3) & 0x04040404)
		| ((v0 >> 4) & 0x01010101)
		| ((v1 >> 0) & 0x80808080)
		| ((v1 >> 1) & 0x20202020)
		| ((v1 >> 2) & 0x08080808)
		| ((v1 >> 3) & 0x02020202);
	right = ((v0 >> 1) & 0x04040404)
		| ((v0 << 2) & 0x10101010)
		| ((v0 << 5) & 0x40404040)
		| ((v1 << 0) & 0x08080808)
		| ((v1 << 3) & 0x20202020)
		| ((v1 << 6) & 0x80808080);
	left = ((left << 6) & 0x33003300)
		| (left & 0xcc33cc33)
		| ((left >> 6) & 0x00cc00cc);
	v0 = ((left << 12) & 0x0f0f0000)
		| (left & 0xf0f00f0f)
		| ((left >> 12) & 0x0000f0f0);
	right = ((right << 6) & 0x33003300)
		| (right & 0xcc33cc33)
		| ((right >> 6) & 0x00cc00cc);
	v1 = ((right << 12) & 0x0f0f0000)
		| (right & 0xf0f00f0f)
		| ((right >> 12) & 0x0000f0f0);
	left = v0 & 0xfffffff0;
	right = (v1 & 0xffffff00) | ((v0 << 4) & 0xf0);

	keycompperm(left, right, ek);
}

static uchar parity[128] =
{
	0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 
	0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 
	0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f, 
	0x31, 0x32, 0x34, 0x37, 0x38, 0x3b, 0x3d, 0x3e, 
	0x40, 0x43, 0x45, 0x46, 0x49, 0x4a, 0x4c, 0x4f, 
	0x51, 0x52, 0x54, 0x57, 0x58, 0x5b, 0x5d, 0x5e, 
	0x61, 0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e, 
	0x70, 0x73, 0x75, 0x76, 0x79, 0x7a, 0x7c, 0x7f, 
	0x80, 0x83, 0x85, 0x86, 0x89, 0x8a, 0x8c, 0x8f, 
	0x91, 0x92, 0x94, 0x97, 0x98, 0x9b, 0x9d, 0x9e, 
	0xa1, 0xa2, 0xa4, 0xa7, 0xa8, 0xab, 0xad, 0xae, 
	0xb0, 0xb3, 0xb5, 0xb6, 0xb9, 0xba, 0xbc, 0xbf, 
	0xc1, 0xc2, 0xc4, 0xc7, 0xc8, 0xcb, 0xcd, 0xce, 
	0xd0, 0xd3, 0xd5, 0xd6, 0xd9, 0xda, 0xdc, 0xdf, 
	0xe0, 0xe3, 0xe5, 0xe6, 0xe9, 0xea, 0xec, 0xef, 
	0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe,
};

/*
 *  convert a 7 byte key to an 8 byte one
 */
void
des56to64(uchar *k56, uchar *k64)
{
	u32int hi, lo;

	hi = ((u32int)k56[0]<<24)|((u32int)k56[1]<<16)|((u32int)k56[2]<<8)|k56[3];
	lo = ((u32int)k56[4]<<24)|((u32int)k56[5]<<16)|((u32int)k56[6]<<8);

	k64[0] = parity[(hi>>25)&0x7f];
	k64[1] = parity[(hi>>18)&0x7f];
	k64[2] = parity[(hi>>11)&0x7f];
	k64[3] = parity[(hi>>4)&0x7f];
	k64[4] = parity[((hi<<3)|(lo>>29))&0x7f];
	k64[5] = parity[(lo>>22)&0x7f];
	k64[6] = parity[(lo>>15)&0x7f];
	k64[7] = parity[(lo>>8)&0x7f];
}

/*
 *  convert an 8 byte key to a 7 byte one
 */
void
des64to56(uchar *k64, uchar *k56)
{
	u32int hi, lo;

	hi = (((u32int)k64[0]&0xfe)<<24)|(((u32int)k64[1]&0xfe)<<17)|(((u32int)k64[2]&0xfe)<<10)
		|((k64[3]&0xfe)<<3)|(k64[4]>>4);
	lo = (((u32int)k64[4]&0xfe)<<28)|(((u32int)k64[5]&0xfe)<<21)|(((u32int)k64[6]&0xfe)<<14)
		|(((u32int)k64[7]&0xfe)<<7);

	k56[0] = hi>>24;
	k56[1] = hi>>16;
	k56[2] = hi>>8;
	k56[3] = hi>>0;
	k56[4] = lo>>24;
	k56[5] = lo>>16;
	k56[6] = lo>>8;
}

void
key_setup(uchar key[7], ulong *ek)
{
	uchar k64[8];

	des56to64(key, k64);
	des_key_setup(k64, ek);	
}