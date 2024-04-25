import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    console.log(dto)
    //hash
    const hash = await bcrypt.hash(dto.password, 10);
    console.log(hash);
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });
    return user;
  }

  signin() {
    return { msg: 'im signed in!' };
  }
}
