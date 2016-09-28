/*
 * polymorphism.c
 *
 *  Created on: 21 sept. 2016
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

typedef struct{
	int x, y;
}point_t;

typedef struct{
	point_t center;
	int r;
}circle_t;

int main(){
	circle_t c;
	c.r = 1;
	c.center.x = c.center.y = 0;
	return 0;
}
