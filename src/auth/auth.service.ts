import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import { hash, compare } from 'bcrypt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    //hash
    try {
      const hashPassword = await hash(dto.password, 8);
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash: hashPassword,
        },
      });
      delete user.hash;
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials were taken');
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    const user = this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Credentials are Incorrect');

    const passwordMatch = await compare(dto.password, (await user).hash);

    if (!passwordMatch) throw new ForbiddenException('Invalid credentials');

    delete (await user).hash;
    return user;
  }
}
