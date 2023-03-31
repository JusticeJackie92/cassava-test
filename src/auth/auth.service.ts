import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { RegisterUserDto } from './dto/register-dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-dto';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from '../utils/contansts';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async register(registerDto: RegisterUserDto) {
    const { email, username, password, confirmHashPassword } = registerDto;
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      throw new BadRequestException('Email already exist');
    }
    const hashedPassword = await this.hashPassword(password);
    await this.prisma.user.create({
      data: {
        email,
        username,
        hashedPassword,
        confirmHashPassword,
      },
    });
    return { message: 'Registration Was Successful' };
  }
  async login(loginDto: LoginUserDto, req: Request, res: Response) {
    const { email, password } = loginDto;
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });
    if (!existingUser) {
      throw new BadRequestException('Wrong Credentials');
    }

    const isMatch = await this.comparePassword({
      password,
      hash: existingUser.hashedPassword,
    });

    if (!isMatch) {
      throw new BadRequestException('Wrong Credentials');
    }
    const token = await this.signToken({
      id: existingUser.id,
      email: existingUser.email,
    });
    if (!token) {
      throw new ForbiddenException();
    }
    res.cookie('token', token);
    //token authentication signing and returning to the user
    return res.send({ message: 'Logged in successfully' });
  }
  async logout(req: Request, res: Response) {
    res.clearCookie('token');
    return res.send({ message: 'Logged out Successfully' });
  }
  async hashPassword(password: string) {
    const saltOrRounds = 10;
    return await bcrypt.hash(password, saltOrRounds);
  }
  async comparePassword(args: { password: string; hash: string }) {
    return await bcrypt.compare(args.password, args.hash);
  }
  async signToken(args: { id: string; email: string }) {
    const payload = args;
    return this.jwt.signAsync(payload, { secret: jwtSecret });
  }
}
