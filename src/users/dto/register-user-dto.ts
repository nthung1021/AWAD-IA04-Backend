import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator'

export class RegisterUserDto {
    @IsString()
    @IsNotEmpty()
    name: string
    
    @IsEmail()
    @IsNotEmpty()
    email: string

    @IsString()
    @MinLength(8, { message: 'Password must be at least 8 characters'})
    password: string
}