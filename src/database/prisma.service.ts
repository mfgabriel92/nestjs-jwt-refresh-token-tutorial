import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super();
  }

  onModuleInit() {
    console.log('Method not implemented.');
  }

  onModuleDestroy() {
    console.log('Method not implemented.');
  }
}
