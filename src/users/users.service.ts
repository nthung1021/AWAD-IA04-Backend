import { ConflictException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { DatabaseService } from 'src/database/database.service'
import { User } from '@prisma/client'
import * as bcrypt from 'bcrypt'

@Injectable()
export class UsersService {
  constructor(
    private readonly databaseService: DatabaseService,
    private readonly jwtService: JwtService
  ) {}

  private createAccessToken(user: User) {
    const payload = { sub: user.id, email: user.email };
    return this.jwtService.sign(payload, { expiresIn: '15m' });
  }

  private createRefreshToken(user: User) {
    const payload = { sub: user.id };
    return this.jwtService.sign(payload, { expiresIn: '7d' });
  }

  async validateUser(email: string, password: string) {
    const user = await this.databaseService.user.findUnique({ where: { email } });
    if (!user) return null;
    const matched = await bcrypt.compare(password, user.password);
    if (!matched) return null;
    return user;
  }

  async register(name: string, email: string, password: string) {
    try {
      const salt = Number(10)
      const hashedPass = await bcrypt.hash(password, salt)

      const user = await this.databaseService.user.create({
          data: { name, email, password: hashedPass },
          select: { id: true, name: true, email: true },
      })

      return user
    } catch (error: any) {
      if (error?.code === 'P2002') {
        const target: string[] = Array.isArray(error?.meta?.target)
          ? error.meta.target
          : [String(error?.meta?.target ?? '')];

        const field = target.find((t) => t === 'email' || t === 'name') ?? 'unknown';
        const message =
          field === 'email'
            ? 'Email already exists.'
            : field === 'name'
            ? 'Name already exists.'
            : 'The value is already taken.';

        // Include `field` in the response body for the frontend
        throw new ConflictException({ message, field, code: 'UNIQUE_CONSTRAINT' });
      }
      throw new InternalServerErrorException('Failed to create user.')
    }
  }

  async login(email: string, password: string) {
    const user = await this.validateUser(email, password);
    if (!user) throw new UnauthorizedException('Email or password is incorrect');

    const accessToken = this.createAccessToken(user);
    const refreshTokenPlain = this.createRefreshToken(user);

    // Hash refresh token before storing
    const hashedRefresh = await bcrypt.hash(refreshTokenPlain, Number(process.env.BCRYPT_SALT_ROUNDS));
    await this.databaseService.user.update({
      where: { id: user.id },
      data: { refreshToken: hashedRefresh },
    });

    return {
      accessToken,
      refreshToken: refreshTokenPlain, // send plain to client; only hashed stored server-side
      user: { id: user.id, email: user.email, name: user.name },
    };
  }

  async refresh(refreshToken: string) {
    try {
      // verify token signature and expiration using jwt.verify
      const payload = this.jwtService.verify<{ sub: number }>(refreshToken);
      const userId = payload.sub;
      const user = await this.databaseService.user.findUnique({ where: { id: userId } });
      if (!user || !user.refreshToken) throw new UnauthorizedException('Invalid refresh token');

      // Compare provided refresh token with hashed stored one
      const match = await bcrypt.compare(refreshToken, user.refreshToken);
      if (!match) throw new UnauthorizedException('Invalid refresh token');

      // Issue new access token (and optionally new refresh token)
      const newAccessToken = this.createAccessToken(user);
      const newRefreshToken = this.createRefreshToken(user);

      // Store new hashed refresh token, replacing old one
      const hashedRefresh = await bcrypt.hash(newRefreshToken, Number(process.env.BCRYPT_SALT_ROUNDS));
      await this.databaseService.user.update({
        where: { id: user.id },
        data: { refreshToken: hashedRefresh },
      });

      return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    } catch (err) {
      // JWT verification failure or bcrypt mismatch
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async findUser(userId: number) {
    try {   
      const user = await this.databaseService.user.findUnique({ 
        where: { id: userId }, 
        select: { id: true, email: true, name: true } 
      });
      if (!user) throw new UnauthorizedException('No user found');
      return user;
    } catch (err) {
      throw new InternalServerErrorException('Failed to get user info.')
    }
  }

  async logout(userId: number) {
    // Clear stored refresh token
    await this.databaseService.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
    return { ok: true };
  }
}
