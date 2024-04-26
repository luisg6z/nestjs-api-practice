import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import { hash } from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    console.log(dto.password);
    //hash
    const hashPassword = await hash(dto.password, 8);
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash: hashPassword,
      },
    });
    return user;
  }

  signin() {
    return { msg: 'im signed in!' };
  }
}
