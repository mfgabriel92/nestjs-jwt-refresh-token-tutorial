import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CurrentUser, Public } from './decorators/index';
import { SignInDto, SignUpDto } from './dtos/index';
import { RefreshTokenGuard } from './guards/index';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('/sign-up')
  async signUp(@Body() data: SignUpDto): Promise<Tokens> {
    return await this.authService.signUp(data);
  }

  @Public()
  @Post('/sign-in')
  @HttpCode(HttpStatus.OK)
  async signIn(@Body() data: SignInDto): Promise<Tokens> {
    return await this.authService.signIn(data);
  }

  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  async logout(@CurrentUser() user: any) {
    await this.authService.logout(user['sub']);
  }

  @Public()
  @UseGuards(RefreshTokenGuard)
  @Post('/refresh-token')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@CurrentUser() user: any) {
    return await this.authService.refreshToken(
      user['sub'],
      user['refreshToken'],
    );
  }
}
