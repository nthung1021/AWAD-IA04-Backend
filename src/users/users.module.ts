import { Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UsersController } from './users.controller'
import { UsersService } from './users.service'
import { DatabaseModule } from 'src/database/database.module'
import { JwtStrategy } from './jwt-strategy';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '15m' },
    }),
  ],
  providers: [UsersService, JwtStrategy, DatabaseModule],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UserModule {}
