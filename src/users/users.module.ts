import { Module } from '@nestjs/common'
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UsersController } from './users.controller'
import { UsersService } from './users.service'
import { JwtStrategy } from './jwt-strategy';
import { DatabaseService } from 'src/database/database.service';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '15m' },
    }),
  ],
  providers: [UsersService, JwtStrategy, DatabaseService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
