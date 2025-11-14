import { Body, Controller, Post, HttpCode, HttpStatus } from '@nestjs/common'
import { UsersService } from './users.service'
import { RegisterUserDto } from './dto/register-user-dto'

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
}
