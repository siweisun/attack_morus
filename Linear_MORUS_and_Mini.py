# -*- coding: utf-8 -*-
"""
Created on Wed Oct 10 15:22:29 2018

@author: LENOVO
"""

from gurobipy import *
from standard import *
import time

class genVars_MORUS:
    
    def __init__(self, length_register):
        self.len_Register = length_register

        
    def genVars_inputRegister(self, r, subr, index):
        return ['S' + str(index) + '_' + str(j) + '_sr' + str(subr) + '_r' + str(r) for j in range(self.len_Register)]
    
    def genVars_keyStream(self, r):
        return ['C_' + str(j) + '_r' + str(r) for j in range(self.len_Register)]
    
    def genVars_outputAnd(self, r, index):
        return ['OAnd' + str(index) + '_' + str(j) + '_r' + str(r) for j in range(self.len_Register)]
    
    def genVars_inputAnd_first(self, r, index):
        return['IAnd_f' + str(index) + '_' + str(j) + '_r' + str(r) for j in range(self.len_Register)]
        
    def genVars_inputAnd_second(self, r, index):
        return ['IAnd_s' + str(index) + '_' + str(j) + '_r' + str(r) for j in range(self.len_Register)]
    
    def genVars_dummay(self, r, subr, index):
        return ['Dum_f' + str(index) + '_' + str(j) + '_sr' + str(subr) + '_r' + str(r) for j in range(self.len_Register)]
    
    def genVars_outputAnd_additional(self, r):
        return ['OAnd_add' + '_' + str(j) + '_r' + str(r) for j in range(self.len_Register)]
    
    def genVars_inputAnd_additional_first(self, r):
        return ['IAnd__add_f' + '_' + str(j) + '_r' + str(r) for j in range(self.len_Register)]
    
    def genVars_inputAnd_additional_second(self, r):
        return ['IAnd__add_s' + '_' + str(j) + '_r' + str(r) for j in range(self.len_Register)]
 
    def genVars_Message(self, r):
        return ['Mess_' + str(j) + '_r' + str(r) for j in range(self.len_Register)]
    
class BasicConstr_linear:
    def getConstraints_Branch(Input_Vars, Dummary_Var):
        '''
        >> BasicConstr_linear.getConstraints_Branch(['a','b'],'c')
        >> ['a + b - 2 c = 0']
        '''
        Constr = [' + '.join(Input_Vars) + ' - 2 ' + Dummary_Var + ' = 0']     
        return Constr        
        
    def getConstraints_XOR(Input_Vars):
        '''
         >> BasicConstr_linear.getConstraints_XOR(['a','b','c'])
         >> ['a - b = 0', 'a - c = 0']
        '''
        n = len(Input_Vars)
        Constr = []
        for i in range(1, n):
            Constr = Constr + [Input_Vars[0] + ' - ' + Input_Vars[i] + ' = 0']
        return Constr
    
    def getConstraints_AND(Input1, Input2, Output0):
        '''
        >> BasicConstr_linear.getConstraints_AND('a','b','c')
        >> ['c - a >= 0', 'c - b >= 0']
        '''
        Constr = []
        Constr = Constr + [Output0 + ' - ' + Input1 + ' >= 0']
        Constr = Constr + [Output0 + ' - ' + Input2 + ' >= 0']
        return Constr
    
    def getConstraints_Rot_on_word(Input, Output, len_word, shiftbit):
        '''
        >> BasicConstr_linear.getConstraints_Rot_on_word(['a1','b1','c1','d1','e1','f1'],['a2','b2','c2','d2','e2','f2'], 3, 1)
        >>
        ['b1 - a2 = 0',
         'c1 - b2 = 0',
         'a1 - c2 = 0',
         'e1 - d2 = 0',
         'f1 - e2 = 0',
         'd1 - f2 = 0']
        '''       
        n = len(Input)//len_word
        Constr = []
        for j in range(n):
            In0 = Input[len_word*j : len_word*(j + 1)]
            Out0 = Output[len_word*j : len_word*(j + 1)]
            for h in range(len_word):
                Constr = Constr + [In0[(h + shiftbit) % len_word] + ' - ' + Out0[h] + ' = 0']
        return Constr
        
    @staticmethod
    def getVariables_From_Constraints(C):
        V = set([])
        for s in C:
            temp = s.strip()
            temp = temp.replace('+', ' ')
            temp = temp.replace('-', ' ')
            temp = temp.replace('>=', ' ')
            temp = temp.replace('<=', ' ')
            temp = temp.replace('=', ' ')
            temp = temp.split()
            for v in temp:
                if not v.isdecimal():
                    V.add(v)

        return V    
    
class LinearCryptanalysis_MORUS:
    
    def __init__(self, length_register, length_word, shift_word, shift):
        self.len_Register = length_register
        self.len_Word = length_word 
        self.b = shift_word
        self.w = shift

    def getConstraints_subround(self, r, subr):
        Vars = genVars_MORUS(self.len_Register)
        KeyStream = Vars.genVars_keyStream(r)
        
        if subr < 4:            
            Input_S = []
            Output_S = []
            for j in range(5):
                Input_S.append(Vars.genVars_inputRegister(r, subr, j))        
                Output_S.append(Vars.genVars_inputRegister(r, subr + 1, j))
        else:
            Input_S = []
            Output_S = []
            for j in range(5):
                Input_S.append(Vars.genVars_inputRegister(r, subr, j))        
                Output_S.append(Vars.genVars_inputRegister(r + 1, 0, j))            

        
        Output_And = Vars.genVars_outputAnd(r, subr)                                                                                                   
        Input0_And= Vars.genVars_inputAnd_first(r, subr)
        Input1_And = Vars.genVars_inputAnd_second(r, subr)
        
        Input0_And_additional = Vars.genVars_inputAnd_additional_first(r)
        Input1_And_additional = Vars.genVars_inputAnd_additional_second(r)
       
        
        Constr = []
        
        #constrains for the branch
        if subr == 0:
            for index in [subr]:
                Dummary = Vars.genVars_dummay(r, subr, index)
                for j in range(self.len_Register):
                    Constr = Constr + BasicConstr_linear.getConstraints_Branch([Input_S[index][j], KeyStream[j], Output_And[j]], Dummary[j])                
            for index in [(subr + 1)%5]:
                Dummary = Vars.genVars_dummay(r, subr, index)
                for j in range(self.len_Register):
                    Constr = Constr + BasicConstr_linear.getConstraints_Branch([KeyStream[(j - self.w[2])% self.len_Register], Input_S[index][j], Output_S[index][j], Input0_And[j]], Dummary[j])
            for index in [(subr + 2)%5]:
                Dummary = Vars.genVars_dummay(r, subr, index)
                for j in range(self.len_Register):
                    Constr = Constr + BasicConstr_linear.getConstraints_Branch([Input0_And_additional[j], Input_S[index][j], Output_S[index][j], Input1_And[j]], Dummary[j])                
            for index in [(subr + 3)%5]:       
                Dummary = Vars.genVars_dummay(r, subr, index)
                for j in range(self.len_Register):
                    Constr = Constr + BasicConstr_linear.getConstraints_Branch([Input1_And_additional[j], Input_S[index][j], Output_S[index][(j - self.w[subr])% self.len_Register], Output_And[j]], Dummary[j])
        else:
            for j in range(self.len_Register):
                Constr = Constr + [Input_S[subr][j] + ' - ' + Output_And[j] + ' = 0']
            for index in [(subr + 1)%5]:
                Dummary = Vars.genVars_dummay(r, subr, index)
                for j in range(self.len_Register):
                    Constr = Constr + BasicConstr_linear.getConstraints_Branch([Input_S[index][j], Output_S[index][j], Input0_And[j]], Dummary[j])
            for index in [(subr + 2)%5]:
                Dummary = Vars.genVars_dummay(r, subr, index)
                for j in range(self.len_Register):
                    Constr = Constr + BasicConstr_linear.getConstraints_Branch([Input_S[index][j], Output_S[index][j], Input1_And[j]], Dummary[j])                
            for index in [(subr + 3)%5]:       
                Dummary = Vars.genVars_dummay(r, subr, index)
                for j in range(self.len_Register):
                    Constr = Constr + BasicConstr_linear.getConstraints_Branch([Input_S[index][j], Output_S[index][(j - self.w[subr])% self.len_Register], Output_And[j]], Dummary[j])
             
        #Constraints for the AND
        for j in range(self.len_Register):
            Constr = Constr + BasicConstr_linear.getConstraints_AND(Input0_And[j], Input1_And[j], Output_And[j])
        #Constraints for rotation on each word
        for j in range(self.len_Register):
            Constr = Constr + BasicConstr_linear.getConstraints_Rot_on_word(Output_And, Output_S[subr], self.len_Word, self.b[subr])

        #Constraints for the rest register
        for j in range(self.len_Register):
            Constr = Constr + [Input_S[(subr + 4) % 5][j] + ' - ' + Output_S[(subr + 4) % 5][j] + ' = 0']

        return Constr
    
    
    def getConstraints_additional_AND_keystream(self, r):
        Vars = genVars_MORUS(self.len_Register)
        A0 = Vars.genVars_inputAnd_additional_first(r)
        A1 = Vars.genVars_inputAnd_additional_second(r)
        B = Vars.genVars_outputAnd_additional(r)
        Keystream = Vars.genVars_keyStream(r)
        
        Constr = []
        #Constraints for the additional AND operation
        for j in range(self.len_Register):
            Constr = Constr + BasicConstr_linear.getConstraints_AND(A0[j], A1[j], B[j])
        
        for j in range(self.len_Register):
            Constr = Constr + BasicConstr_linear.getConstraints_XOR([B[j], Keystream[j]])
        return Constr
    
    def getConstraints_additional(self, TotalR):
        Constr = []
        Input_S = []
        Output_S = []
        Vars = genVars_MORUS(self.len_Register)
        for i in range(5):
            Input_S = Input_S + Vars.genVars_inputRegister(0, 0, i)
            Output_S = Output_S + Vars.genVars_inputRegister(TotalR, 0, i)
            
        Constr = Constr + [' + '.join(Input_S) + ' = 0']
        Constr = Constr + [' + '.join(Output_S) + ' = 0']
        
        Keystream = []
        for i in range(TotalR):
            Keystream = Keystream + Vars.genVars_keyStream(i)
        Constr = Constr + [' + '.join(Keystream) + ' >= 1']
        return Constr
    
    
    def genObjective(self, TotalR):
        Var_obj = []
        Vars = genVars_MORUS(self.len_Register)
        for i in range(TotalR):
            for j in range(5):
                Var_obj = Var_obj + Vars.genVars_outputAnd(i, j)
            Var_obj = Var_obj + Vars.genVars_outputAnd_additional(i)
        Obj = ' + '.join(Var_obj)
        return Obj
        
    
    def getConstraints_RoundFun(self, r):
        Constr = []
        for subr in range(5):
            Constr = Constr + self.getConstraints_subround(r, subr)
        Constr = Constr + self.getConstraints_additional_AND_keystream(r)
        return Constr
    
                        
                    
        
    def genModel(self, TotalR, Name):
        Constr = []
        for i in range(TotalR):
            Constr = Constr + self.getConstraints_RoundFun(i)
        Constr = Constr + self.getConstraints_additional(TotalR)
      
        V = BasicConstr_linear.getVariables_From_Constraints(Constr)
        
        fid=open('./Linear_' + Name + str(5*self.len_Register) + '_r' + str(TotalR) + '.lp','w')
        fid.write('Minimize')
        fid.write('\n')
        fid.write(self.genObjective(TotalR))
        fid.write('\n')
        fid.write('Subject To')
        fid.write('\n')
        for c in Constr:
            fid.write(c)
            fid.write('\n')
        
        GV = []
        BV =[]
        for v in V:
            if v[0] == 'D':
                GV.append(v)
            else:
                BV.append(v)
                

        fid.write('Binary'+'\n')
        for bv in BV:
            fid.write(bv+'\n')
            
        fid.write('Generals'+'\n')
        for gv in GV:
            fid.write(gv+'\n')           
        
        fid.close()
    
        
def cmd(len_Register, len_Word, TotalR, Name):
    if len_Register == 128 or len_Register == 32:
        b = [5, 31, 7, 22, 13]
        w = [32, 64, 96, 64, 32]
    elif len_Register == 256 or len_Register == 64:
        b = [13, 46, 38, 7, 4]
        w = [64, 128, 192, 128, 64]
        
    a = LinearCryptanalysis_MORUS(len_Register, len_Word, b, w)
    a.genModel(TotalR, Name) 
    
    modelname =  'Linear_' + Name + str(5*len_Register) + '_r' + str(TotalR) 

    
