import { Body, Controller, Post, HttpCode, HttpStatus, Req, UseGuards, UnauthorizedException } from '@nestjs/common'
import { UsersService } from './users.service'
import { RegisterUserDto } from './dto/register-user-dto'
import { LoginDto } from './dto/login-user-dto'
import { RefreshDto } from './dto/refresh-user-dto'
import type { Request } from 'express';
import { JwtAuthGuard } from './jwt-auth-guard';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterUserDto) {
    const user = await this.userService.register(dto.name, dto.email, dto.password)
    
    return {
      message: 'User registered successfully',
      data: user
    }
  }

  @Post('login')
  async login(@Body() dto: LoginDto) {
    return this.userService.login(dto.email, dto.password);
  }

  @Post('refresh')
  async refresh(@Body() dto: RefreshDto) {
    return this.userService.refresh(dto.refreshToken);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Req() req: Request) {
    // @ts-ignore
    const user = req.user as any;
    if (!user || !user.sub) throw new UnauthorizedException();
    await this.userService.logout(user.sub);
    return { message: 'Logged out' };
  }
}
