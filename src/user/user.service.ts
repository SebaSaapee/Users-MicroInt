import { UserDTO } from './dto/user.dto';
import { HttpStatus, Injectable, HttpException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { USER } from 'src/common/models/models';
import { IUser } from 'src/common/interfaces/user.interface';
import * as nodemailer from 'nodemailer';

@Injectable()
export class UserService {

  async findByUsername(username: string) {
    return await this.model.findOne({ username });
  }
  constructor(@InjectModel(USER.name) private readonly model: Model<IUser>) {}

  async checkPassword(password: string, passwordDB: string): Promise<boolean> {
    return await bcrypt.compare(password, passwordDB);
  }

  async findByEmail(email: string) {
    return await this.model.findOne({ email });
  }

  async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
  }

  async create(userDTO: UserDTO): Promise<IUser> {
    const hash = await this.hashPassword(userDTO.password);
    const newUser = new this.model({ ...userDTO, password: hash });
    return await newUser.save();
  }

  async findAll(): Promise<IUser[]> {
    return await this.model.find();
  }

  async findOne(id: string): Promise<IUser> {
    return await this.model.findById(id);
  }

  async update(id: string, userDTO: UserDTO): Promise<IUser> {
    const hash = await this.hashPassword(userDTO.password);
    const user = { ...userDTO, password: hash };
    return await this.model.findByIdAndUpdate(id, user, { new: true });
  }

  async delete(id: string) {
    await this.model.findByIdAndDelete(id);
    return {
      status: HttpStatus.OK,
      msg: 'Deleted',
    };
  }

  // Métodos para recuperación de contraseña
  async generateRecoveryCode(email: string) {
    const user = await this.findByEmail(email);
    console.log(user)
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const recoveryCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Aquí podrías guardar el recoveryCode en la base de datos asociado al usuario
    user.recoveryCode = recoveryCode;
    await user.save();

    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: false, // Usa SSL/TLS
      
    });
    
    // Ejemplo de enviar correo sin autenticación
    const mailOptions = {
      from: email,
      to: email,
      subject: 'Prueba de correo sin autenticación desde Nodemailer',
      text: 'Hola, este es un correo de prueba enviado desde Nodemailer sin autenticación.',
    };
    console.log(mailOptions)
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error al enviar correo:', error);
        // Aquí puedes manejar el error de manera específica según tu lógica de aplicación
        // Por ejemplo, podrías retornar un mensaje de error o lanzar una excepción.
      } else {
        console.log('Correo enviado:', info.response);
        // Aquí puedes manejar la respuesta exitosa, si es necesario.
      }
    });
  }

  async resetPassword(email: string, recoveryCode: string, newPassword: string) {
    const user = await this.findByEmail(email);
    if (!user || user.recoveryCode !== recoveryCode) {
      throw new HttpException('Invalid recovery code', HttpStatus.BAD_REQUEST);
    }

    user.password = await this.hashPassword(newPassword);
    user.recoveryCode = undefined; // Opcional: Eliminar el código de recuperación después de usarlo
    await user.save();

    return { message: 'Password reset successfully' };
  }
}