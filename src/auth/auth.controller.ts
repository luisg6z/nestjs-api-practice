import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authServices: AuthService) {}
  @Post('signup')
  signup(@Body() dto: AuthDto) {
    return this.authServices.signup(dto);
  }

  @Post('signin')
  signin() {
    return this.authServices.signin();
  }
}
