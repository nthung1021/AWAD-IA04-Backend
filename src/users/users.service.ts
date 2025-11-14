import { ConflictException, Injectable, InternalServerErrorException } from '@nestjs/common'
import { DatabaseService } from 'src/database/database.service'
import * as bcrypt from 'bcrypt'

@Injectable()
export class UsersService {
  constructor(private readonly databaseService: DatabaseService) {}

  // Register new user
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

  // Get user by name
  async findByName(name: string) {
    return this.databaseService.user.findFirst({ where: { name } })
  }

  // Get user by email
  async findByEmail(email: string) {
    return this.databaseService.user.findUnique({ where: { email } })
  }
}
