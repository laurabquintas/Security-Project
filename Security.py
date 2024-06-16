from asyncore import poll3
from cProfile import label
from contextvars import copy_context
import os
import json
import copy
from re import S
from tkinter import N

#classes definitions: all hidden atributtes 

#Pattern
class Pattern:
    '''Representation of a vulnerability pattern, including all its components, used in class Policy
    O(1)''' 

    def __init__(self, dict_pattern):\
        self.__pattern = dict_pattern

    def __str__(self):
        ''' Default __str__ that ensures that Patterns are printed in the same way a Pattern is added manually by the user.
        O(n)'''
        return str(self.__pattern)
    
    def __repr__(self):
        ''' Default __repr__ that returns the pattern as a string even if it is by other classes prints.
        O(n)'''
        return str(self.__pattern)

    def get_vulnerability(self):
        ''' Returns the vulnerability pattern
        O(1)'''
        return self.__pattern.get('vulnerability') 

    def get_sanitizers(self):
        '''Returns the sanitizers associated to the vulnerability pattern
        O(1)'''
        return self.__pattern.get('sanitizers')

    def is_source(self, other_source):
        '''Verifies if the source received is part of the vulnerability pattern
        O(n)''' 
        return other_source in self.__pattern.get('sources')

    def is_sanitizer(self, other_sanitizer):
        '''Verifies if the sanitizer received is part of the vulnerability pattern
        O(n)''' 
        return other_sanitizer in self.__pattern.get('sanitizers')

    def is_sink(self, other_sink):
        '''Verifies if the sink received is part of the vulnerability pattern
        O(n)''' 
        return other_sink in self.__pattern.get('sinks')

#Flow
class Flow:
    '''Represents an information flow from a source, it's used in label class 
    O(1)'''

    def __init__(self, source_name):
        self.__source = source_name

    def __str__(self):
        ''' Default __str__ that ensures that Flows are printed as their source_name. 
        O(1) '''
        return str(self.__source) 

    def __repr__(self):
        ''' Default __repr__ that shows the flow with the respective source name 
        O(1)'''
        return 'Flow(' + str(self.__source) +')'

    def __eq__(self, other_flow):
        ''' Default __eqq__ that ensures that Flows are equal when compared. 
        O(1)'''
        return self.same_source(other_flow)
    
    def get_source(self):
        '''Returns the source associated too the Flow
        O(1) '''
        return self.__source
    
    def same_source(self, other_flow):
        '''Verifies if the Flow received is the same, if it has the same source 
        O(1) '''
        if isinstance(other_flow, Flow):  
            return (self.__source == other_flow.__source)
    
    def copy_flow(self):
        '''Creates a new flow equal
        O(1) ''' 
        return copy.copy(self)

    def __hash__(self):
        '''Makes the Flow hashable and makes use of the hash of the source name input
        O(1) '''
        return hash(self.__source)

#Policy
class Policy:
    '''Represents the current information flow policy wich is a list of patterns and determines which Flows are illegal 
    O(1)'''

    def __init__(self):
        self.__policy = {}
        self.__vulnerabilities = []

    def __str__(self): 
        ''' Default __str__ that ensures that policys are printed in ordered and sorted way. 
        O(plog(p) + pn) '''

        sort_policy= sorted(self.__policy.values(), key=lambda d: d.get_vulnerability())
        return str(sort_policy)
    
    def __repr__(self):
        ''' Default __repr__ that shows the policy as it is
        O(pn)'''
        return str(self.__policy)
    
    def __eq__(self, other_policy):
        '''' Default __eq__ method that returns true if the policies are equal 
        O(pn) '''
        return self.__policy == other_policy.get_policy()
    
    def add_pattern(self, pattern):
        '''Verifies if there's no pattern inserted with the same name and if not it appends it to both list of patterns and list of vulnerabilities
        O(1)'''
        if pattern.get_vulnerability() not in self.__policy:
            self.__policy[pattern.get_vulnerability()]= pattern
         
    def delete_pattern(self, name):
        '''Verifies if there's no pattern inserted with the same name and if so it deletes it from both list of patterns and list of vulnerabilities
        O(1) '''  
        if name in self.__policy:
            del self.__policy[name]
        else:
            print(f"No pattern named {name}")

    def get_vulnerabilities(self):
        '''Returns the list of vulnerabilities names of the patterns that are part of the policy list
         O(plogp) on the first that is used, O(1) after - during the rest of the analysis'''   
        return self.updated_vulnerabilities()
    
    def get_policy(self):
        ''' Returns the policy atribute that is hidden.
        O(1)'''
        return self.__policy
        
    def get_vulnerabilities_source(self, source_name):
        '''Returns a list with the vulnerabilities associated with the source 
        O(pn)'''
        vulnerabilities_source = []
        for key,value in self.__policy.items():
            if value.is_source(source_name):
                vulnerabilities_source.append(key)
        return vulnerabilities_source

    def get_vulnerabilities_sanitizer(self, sanitizer_name):
        '''Returns a list with the vulnerabilities associated with the sanitizer 
        O(pn)'''
        vulnerabilities_sanitizer = []
        for key,value in self.__policy.items():
            if value.is_sanitizer(sanitizer_name):
                vulnerabilities_sanitizer.append(key)
        return vulnerabilities_sanitizer

    def get_vulnerabilities_sink(self, sink_name):
        '''Returns a list with the vulnerabilities associated with the sink 
        O(pn) '''
        vulnerabilities_sink = []
        for key,value in self.__policy.items():
            if value.is_sink(sink_name):
                vulnerabilities_sink.append(key)
        return vulnerabilities_sink

    def get_sanitizers_vulnerability(self, vulnerability_name):
        '''Returns the lis of sanitizers associated with the pattern with that vulnerability name
        O(1)'''
        if vulnerability_name in self.__policy:
            return self.__policy[vulnerability_name].get_sanitizers()

    def illegal_flows(self, one_label, sink_name): ###MUDEI mas ainda nao estou muito convencida #Testei e acho que tens que ir buscar o updated_vulns 
        '''Returns a new Label that removes flows in the original label that are associated with patterns that do not have this sink 
        O(pn + p^2)'''  
        new_label = one_label.copy_label()
        for i in self.get_vulnerabilities():
            if str(i) not in self.get_vulnerabilities_sink(sink_name):
                new_label.clear_flows(i)
        return new_label

    def updated_vulnerabilities(self):
        '''Verifies if the list of vulnerabilities is updated with the current policy, and returns the updated list
         O(plogp) on the first that is used, O(1) after - during the rest of the analysis'''
        if len(self.__policy)!=len(self.__vulnerabilities):
            self.__vulnerabilities = sorted(self.__policy.keys(), key=str.lower)
        return self.__vulnerabilities
            
#Label
class Label:
    """Collection of flows that might have influenced a piece of data param policy: Policy object, the policy that guides the analysis complexity: 
    O(1)""" 

    def __init__(self, policy):
        self.__flows_policy = policy
        self.__flows_vulnerability={}

    def __str__(self):
        ''' Default __str__ that ensures that labels are printed as {vulnerabilities:set(flows)}.
        O(pn)'''
        return str(self.__flows_vulnerability)
    
    def __repr__(self):
        ''' Default __repr__ that shows the Label object dictionary of sets of Flows
        O(pn)'''
        return str(self.__flows_vulnerability)

    def __eq__(self,other_label):
        '''Default __eqq__  method that ensures the equality of two labels just when both have the same source and the same dictionary {vulnerabilities:set(flows)}. 
        O(pn)'''
        if isinstance(other_label,Label):
            return self.__flows_vulnerability == other_label.__flows_vulnerability
    
    def __add__(self,other_label):
        '''Default __add__  method that ensures the combination of the labels when a + is used. 
        O(pn)'''
        return self.label_combine(other_label)
    
    def add_if_source(self, source_name):
        '''Adds a new key of vulnerability names that are associated to that source and adds a set of Flows with all its sources, verifies if there isn't already a flow of that source, so the are no repeated.
        O(pn)'''
        for i in self.__flows_policy.get_vulnerabilities_source(source_name):#O(p + pn)
            if i not in self.__flows_vulnerability:  #O(1)
                self.__flows_vulnerability[str(i)]={Flow(source_name)}
            else:
                self.__flows_vulnerability[str(i)].update([Flow(source_name)])
            
    def clear_flows(self, vulnerability_name): ##VER
        '''Deletes the vulnerability name key and its Flow(source) associated if it's present in the label. 
        O(1)'''
        try:
            del self.__flows_vulnerability[str(vulnerability_name)] 
        except:
            pass

    def sanitize(self, sanitizer_name):
        ''' Receives a label (self) and a sanitizer name. Changes (self) label to delete the flows that are associated with vulnerabilities that have that sanitizer. 
        O(pn)''' 
        for i in (self.__flows_policy).get_vulnerabilities_sanitizer(sanitizer_name): 
            self.clear_flows(i)

    def get_flows_vulnerability(self, vulnerability_name):
        ''' Receives a label (self) and a vulnerability name. Returns the set of flows that are associated with that vulnerability in the label (self). 
        O(1)'''
        return self.__flows_vulnerability.get(vulnerability_name)

    def copy_label(self):
        ''' Receives a label (self) and returns a deep copy of itself. Imported the method copy to do so. 
        O(pn)'''
        return copy.deepcopy(self) 
    

    def label_combine(self, other_label):
        ''' Receives two labels and returns a new label wich is a combination of the inputed ones. The first one is copied to merge and the union method of sets is used to avoid repetitions
        O(pn)'''
        merged = self.copy_label()
        if isinstance(other_label,Label):
            for key,value in other_label.__flows_vulnerability.items():
                if key not in merged.get_label():
                    merged.__flows_vulnerability[key]=value
                else:
                    merged.__flows_vulnerability[key]=merged.__flows_vulnerability[key].union(value)
        return merged
   
    def get_label(self):
        ''' Receives a label object (self) and returns de colection {vulnerability:set(flows)} that exists in the label.
        O(1)'''
        return self.__flows_vulnerability
    
#Stack 
class Stack:
    """Stack implementation as a list
    O(1)"""
    def __init__(self):
        """Create new stack"""
        self.__items = []
    
    def __str__(self):
        return str(self.__items)   

    def __repr__(self):
        return str(self.__items)            
    
    def is_empty(self):
        """Check if the stack is empty 
        O(1)"""
        return not bool(self.__items)
    
    def push(self, item):
        """Add an item to the stack
        O(1)"""
        self.__items.append(item)

    def pop(self):
        """Remove an item from the stack
        O(1)"""
        return self.__items.pop()

    def peek(self):
        """Get the value of the top item
        O(1)"""
        return self.__items[-1]

#Context  
class Context(Stack):
    '''Represents the information that is carried by the control flow of the program being analysed in a stack of blocks, keeps track of the labels associated with to the conditions of the block it depends
    O(1)'''
    def __init__(self):
        super().__init__()

    def enter_block_label (self,one_label):
        ''' Receives stack object (self) and a Label that represents the information that is carried by the control flow of the program being analysed and updates the Context Stack with it
        O(pn)'''
        if not self.in_block():
            self.push(one_label)#O(1)
        else:
            self.push(self.peek().label_combine(one_label))#O(pn)
            
    def exit_block (self):
        '''Receives the stack object (self)  and removes the innermost block
        O(1)'''
        self.pop()

    def in_block(self): 
        '''Receives the stack object (self) and verifies if there are already any labels inserted
        O(1)'''
        return not self.is_empty()

    def get_block_label (self):
        '''Receives the stack object (self) and returns the all the implicit flows that affect the current block
        O(1)'''
        if self.in_block():
            return self.peek()

            
#Labelmap
class LabelMap:
    '''Represents a mapping from variable names to labels, keeps track of the information flows that might have affected the current values that are held in the variables of the program
    O(1)'''
    def __init__(self):
        self.__dict={}

    def __str__(self):
        '''Generates a string of the LabelMap
        O(spn)'''
        string = ''
        for key,value in self.__dict.items(): #O(s)
            string += f'{str(key)}->{str(value)} \n' #O(1)  
        return string #O(spn)
    
    def __eq__(self, other_label_map):
        '''Compares the dict of label of self and the input label Map and verifies if they are equal
        O(spn)'''
        return self.get_label_map() == other_label_map.get_label_map() #O(spn)

    def __add__(self,other_labmap):
        '''Enables the use of the labmap_combine with '+' sign to merge labelmaps the self object and the received labelmap 
        O(spn)'''
        return self.labmap_combine(other_labmap)

    def copy_labmap(self):
        '''Generates a deep copy of the LabelMap
        O(spn)'''
        return copy.deepcopy(self)

    def is_labelled(self, var):
        '''Receives the dict object (self) and a string with a name of a variable a returns True if it has a label associated (true) or not (false)
        O(1)'''
        return var in self.__dict #O(1)

    def map_name_to_label(self,var,one_label):
        '''Receives the LabelMap object self, a name as a string and a Label object, and updates self so as to map the given name to the given label. 
        O(1)'''
        self.__dict.update({var : one_label}) #O(1)

    def labmap_combine(self,other_labmap):
        '''Receives the LabelMap object self and another LabelMap object, and returns a new LabelMap object that results from combining the two that were received. 
        O(spn)'''
        merged = self.copy_labmap()#O(spn)
        if isinstance(other_labmap,LabelMap):#O(1)
            for key,value in other_labmap.get_label_map().items():#O(s)
                if key not in merged.get_label_map(): #O(1)
                    merged.get_label_map()[key]=value #O(1)
                else:
                    merged.get_label_map().update({key: merged.get_label_map()[key].label_combine(value)})#O(pn)
        return merged
    
    def get_copy_label(self,var):
        '''receives a string with the name of the variable and copies the label associated with it
        O(pn)'''
        return self.__dict[var].copy_label()
    
    def get_label_map(self):
        '''Receives self object and return the self dictionary with the variables associated with the Labels 
        O(1)'''
        return self.__dict

#Illegal Flows   
class IllegalFlows:
    ''' The IllegalFlows ADT is used to collect all the illegal flows that are discovered during the analysis of the program slice.
    O(1)'''
    def __init__(self, policy):
        self.__illegal_flows = {}
        self.__policy = policy

        
    def __str__(self): 
        '''Prints the illegal flows for each vulnerability name, sorted by lexicographic order of vulnerability name and of source name. 
        O(pn(logn))''' 
        message=''#O(1)
        for i in self.__policy.get_vulnerabilities():#O(p)
            if i in self.__illegal_flows:#O(1)
                message += f'Vulnerability {str(i)} detected! \nIllegal flows: '#O(1)
                b = sorted(self.__illegal_flows.get(i), key=str.lower)#O(nlogn)
                for j in b:#O(n)
                    if j != b[-1]:#O(1)
                        message += str(j) + ', ' #O(1)
                    else:
                        message += str(j) + '\n' #O(1)

                message += f'Recommended sanitizers: {str(self.__policy.get_sanitizers_vulnerability(i))} \n' #O(n) 
            else:
                message += f"Vulnerability {str(i)} not detected. \n" #O(1)
        
        return message #O(1) 
    
    def get_illegal_flows(self, one_label, name_sink): 
        '''Updates the dicionary so as to include any illegal flows that result when information with the given label reaches a sink with the given name.
         O(pn + p^2)''' 

        illegal_flows = self.__policy.illegal_flows(one_label, name_sink) #O(pn + p^2)
        for i in self.__policy.get_vulnerabilities(): #O(p)
            set_flows=illegal_flows.get_flows_vulnerability(i)
            if isinstance(set_flows,set):
                if i not in self.__illegal_flows:
                    self.__illegal_flows.update({i:set()})

                for j in set_flows:
                    string=str(j)+' -> '+str(name_sink)
                    self.__illegal_flows[i].add(string)
            
                


#Analyser
class Analyser:
    ''' The Analyser ADT represents the analysis functionality of the tool. It includes methods for traversing different program constructs and returning the information collected during the traversal O(1)'''

    def __init__(self, policy, illegalflows):
        self.__context = Context()
        self.__policy = policy
        self.__illegalflows = illegalflows
    
    def expr_name(self, ast_node, labelmap):
        '''Receives a new Analyser object self, an AST expression node of the type Name, and a LabelMap object, 
        and returns a new Label object representing the information flows that are carried by the name. 
        O(pn)'''

        if labelmap.is_labelled(ast_node['id']): #O(1)
            label = labelmap.get_copy_label(ast_node['id']) #O(pn)
        else:
            label = Label(self.__policy) #O(1)
        return label #O(1)
    
    def expr_binop(self, ast_node, labelmap):
        '''Receives a new Analyser object self, an AST expression node of the type BinOp, and a LabelMap object, 
        and returns a new Label object representing the information flows that are carried by the whole binary expression.  
        O(s(spn + p^2))''' #### O(s(pn + p^2))

        return self.expr_label(ast_node['right'],labelmap) + self.expr_label(ast_node['left'],labelmap) #O(s(spn + p^2)) # worst case expr_call #### O(s(pn + p^2))
    
    def expr_compare(self, ast_node, labelmap):
        '''Receives a new Analyser object self, an AST expression node of the type Compare, 
        and a LabelMap object, and returns a new Label object representing the information flows that are carried by the whole comparison expression. 
        O(s(spn + p^2))'''

        return self.expr_label(ast_node['comparators'][0],labelmap) + self.expr_label(ast_node['left'], labelmap) #O(s(spn + p^2)) #worst case expr_call #### O(s(pn + p^2))
    
    def expr_call(self, ast_node, labelmap): 
        '''Receives a new Analyser object self, an AST expression node of the type Call, 
        and a LabelMap object, and returns a new Label object representing the information flows that are carried by the function call.  
        O(s(spn + p^2))'''  #### O(s(pn + p^2))
        label=Label(self.__policy) #O(1)  

        for i in ast_node['args']: #O(s)
            label += self.expr_label(i, labelmap) #O(pn)

        context_label = self.__context.get_block_label() #O(1)
        if isinstance(context_label, Label): #O(1)    #### Melhorar: usar in_block
            label += context_label #O(pn)
            
        name = ast_node['func']['id'] #O(1)
        label.add_if_source(name) # O(pn)
        label.sanitize(name) #O(pn)
       
        self.__illegalflows.get_illegal_flows(label,name) #O(pn + p^2)

        return label #O(1)

    def expr_label(self,ast_node, labelmap):
        '''Receives a new Analyser object self, an AST expression node, and a LabelMap object, and returns a new Label object representing the information flows that are carried by the expre  ssion. 
        O(s(spn + p^2))''' #worst case complexity expr_call #### O(s(pn + p^2))
        a= ast_node['ast_type'] #O(1)
        if a == 'Name': #O(1)
            return self.expr_name(ast_node, labelmap)
        elif a == 'BinOp': #O(1)
            return self.expr_binop(ast_node,labelmap)
        elif a == 'Compare': #O(1)
            return self.expr_compare(ast_node, labelmap)
        elif a == 'Call': #O(1)
            return self.expr_call(ast_node,labelmap)#O(s(pn + p^2))
        elif a == 'Expr': #O(1)
            return self.expr_label(ast_node['value'],labelmap)
        else:
            return Label(self.__policy) #O(1)
    
    def traverse_assign(self, ast_node, labelmap):
        '''Receives a new Analyser object self, an AST statement node of the type Assign, and a LabelMap object, and returns a new LabelMap object that is like the one received as argument, but that also takes note of the flows introduced by the assignment. 
        O(s(spn + p^2))'''   #### O(s(pn + p^2))
        thelabel = self.expr_label(ast_node['value'],labelmap)#O(s(spn + p^2))
        context_label = self.__context.get_block_label() #O(1)
        
        if isinstance(context_label,Label):#O(1)   #### Melhorar: usar in_block
          thelabel += context_label #(pn)

        labelmap.map_name_to_label(ast_node['targets'][0]['id'], thelabel) #O(1)
        
        return labelmap

    def traverse_if(self, ast_node, labelmap):
        '''Receives a new Analyser object self, an AST statement node of the type If, and a LabelMap object, and returns a new LabelMap object that is like the one received as argument, but that also takes note of the flows introduced by the if condition. 
        O(O(s^2(spn + p^2)))'''  #### O(s(pn + p^2))
        self.__context.enter_block_label(self.expr_label(ast_node['test'], labelmap) ) #O(s(spn + p^2))

        ifbranch=labelmap.copy_labmap() #O(spn)
        ifbranch=self.traverse(ast_node['body'],ifbranch) #O(s^2(spn + p^2))) #worst case traverse_while
        labelmap=self.traverse(ast_node['orelse'],labelmap) #O(s^2(spn + p^2)) #worst case traverse_while

        self.__context.exit_block() #O(1)

        return ifbranch + labelmap #O(spn)

    
    def traverse_while(self, ast_node, labelmap):
        '''Receives a new Analyser object self, an AST statement node of the type While, and a LabelMap object, and returns a new LabelMap object that is like the one received as argument, but that also takes note of the flows introduced by the while loop. 
        O(s^2(spn + p^2)) '''  #### O(s(pn + p^2))
        self.__context.enter_block_label(self.expr_label(ast_node['test'], labelmap)) #O(s(spn + p^2))

        anterior = labelmap.copy_labmap() #O(spn)
        labelmap = self.traverse(ast_node['body'], labelmap) #### Corrigir: falta combinar com o anterior para tratar do caso com 0 iteracoes
        labelmap_toreturn = anterior #O(1)

        while labelmap != anterior:#O(s)
            anterior = labelmap.copy_labmap() #O(spn)
            labelmap = self.traverse(ast_node['body'], labelmap) 
            labelmap_toreturn += anterior #O(spn)
        
        self.__context.exit_block()#O(1)

        return labelmap_toreturn#O(1)


    def traverse(self, ast_node, labelmap):
        '''Receives a new Analyser object self, an AST statement node, and a LabelMap object, and returns a new LabelMap object that is like the one received as argument, but that also takes note of the flows introduced by the statement.
        O(s^2(spn + p^2))'''   #### O(s(pn + p^2))
       
        if isinstance(ast_node,list):
            for i in ast_node: 
                labelmap = self.traverse(i,labelmap) #O(s^2(spn + p^2))

        else:
            a = ast_node['ast_type']
            if a == 'Assign':
                labelmap = self.traverse_assign(ast_node,labelmap) #O(s(spn + p^2))
            elif a == 'If':
                labelmap = self.traverse_if(ast_node,labelmap) #O(s^2(spn + p^2))
            elif a == 'While':
                labelmap = self.traverse_while(ast_node,labelmap) #O(s^2(spn + p^2))
            elif a == 'Expr':
                self.expr_label(ast_node,labelmap)#O(s(spn + p^2))

        return labelmap

#Read AST File 
def read_ast_file(file_name):
    ''' Reads a .py file that receives as input, converts in json format, and returns the respective .ast file. 
    O(s)'''
    os.system("astexport <"+file_name+"> myveryowntemp")
    with open("myveryowntemp") as fp1:
        ast_json=fp1.read()
    ast=json.loads(ast_json)
    #os.system("del myveryowntemp")
    return ast

#Read Patterns File
def read_patterns_file(cmd):
    ''' Reads a patterns file in json format, and returns the patterns. 
    O(pn)'''
    with open(cmd) as fp2:
        pat_str=fp2.read()
        pat_json=pat_str.replace('\n','')
        patterns=json.loads(pat_json)
    return patterns

#Pretty Print AST
def print_json(json,ident,is_value):
    '''Prints an AST recursively, by analysing every node as a list, dictionary or finally a string. 
    O(s)'''
    try:
        if isinstance(json,list):
            return print_list(json,ident,is_value)
        elif isinstance(json,dict):
            return print_dict(json,ident,is_value)
        else:
            return print(json,end="")
    except:
        print("AST File not compatible.")

#Pretty Print AST - list case
def print_list(lista,ident,is_value):
    '''Case of the current AST node is a list. 
    '''
    is_value=False
    if lista == []:
        print("[]",end="")
    else:
        print("[\n",end="")
        ident +=1
        for i in lista:
            if i != lista[-1]:
                print_json(i,ident,is_value)
                print(",\n",end="")
            else:
                print_json(i,ident,is_value)
                print("\n"+ident*" "+"]",end="")
        ident -=1
        
#Pretty Print AST - dictionary case
def print_dict(dici,ident,is_value):
    '''Case of the current AST node is a dictionary. Only the included keys are printed but the AST order remains. 
    '''
    included_keys={"args", "func", "id", "left", "right", "comparators", "ast_type", "targets","value", "test", "body", "orelse"}
    if is_value:
        ident +=1
        print("{") 
        ident +=1
    else:
        ident +=1
        print(ident*" "+"{") 
        ident +=1
    x = [x for x in dici.keys() if x in included_keys]
    for i in x:
        print(ident*" ",end="")
        print_json(i,ident,is_value)
        print(":",end="")
        is_value=True
        if i != x[-1]:
            print_json(dici[i],ident,is_value)
            print(",")
        else:
            print_json(dici[i],ident,is_value)
            print("\n"+ident*" "+"}",end="")
    ident -=2

#MENU
print('Menu \n a - Perform analysis \n p - Read abstract syntax tree (AST) file \n b - Read vulnerability patterns list (VPL)  \n e - Add Vulnerability \n d - Delete Vulnerabilities \n c - Show current vulnerabilities\n j - pretty printing of json \n x - Exit \n')

#menu command
command = ''

#ast file in json
AST_current = ''

#files names
vpl_file = ''
ast_file = ''

#Policy utilizada
policy_current = Policy()

while command != 'x':
    command = input("\nEnter a command\n")

    if command[0] == 'a':
        '''Analises the AST of the currently stored program slice and returns encoded vulnerabilities and illegal information flows, organized as requested.
        O(pnlogn + s^2(spn + p^2))'''
        illegalflows_current = IllegalFlows(policy_current) #O(1)
        analyser_current = Analyser(policy_current,illegalflows_current) #O(1)
        labelmap_current = LabelMap() #O(1)
        try:
            labelmap_current = analyser_current.traverse(AST_current['body'],labelmap_current) #O(s^2(spn + p^2))
            print(illegalflows_current) #O(pnlogn) 
        except:
            print('Error analysing the program.')

    elif command[0] == 'p':
        '''Read a new Python program slice to analyse from file file_name.
        O(s)'''
        AST_current = ''
        try:
            ast_file=command[2:]
            AST_current = read_ast_file(ast_file)
            print(f"\n AST file: {ast_file} saved. \n ")
        except:
            print('File not compatible or not found')

    elif command[0] == 'b':
        '''Read new base vulnerability patterns from file file_name.
        O(p(p+n))'''
        policy_current = Policy()
        try:
            vpl_file=command[2:]
            s = read_patterns_file(vpl_file)
            for i in s:
                new_pattern=Pattern(i)
                policy_current.add_pattern(new_pattern)
            print(f"\n VPL file: {vpl_file} saved. \n ")
        except:
            print('File not compatible or not found')

    elif command[0] == 'e':
        '''Extend base vulnerabilities with json_pattern. Receives a pattern and adds it to the policy. 
        O(pn) '''
        try:
            new_pattern=Pattern(json.loads(command[2:]))
            policy_current.add_pattern(new_pattern)
            print(f"\n Pattern: {new_pattern.get_vulnerability()} saved. \n ")
        except:
            print('Pattern not compatible')

    elif command[0] == 'd':
        '''Delete vulnerability pattern vuln_name from base. Receives a vulnerability name and deletes it from the policy if it's present on the list
        O(1)'''
        try:
            vuln_name=command[2:]
            policy_current.delete_pattern(vuln_name)
            print(f"\n Pattern {vuln_name} deleted. \n")
        except:
            print('Pattern not found')

    elif command[0] == 'c':
        '''Show current program slice and vulnerability patterns. Prints the AST file e a policy gerada até ao momento.
        O(s + pn)'''
        try:
            print('AST File')
            os.system("type " + ast_file)
            print('\n')
            print(policy_current)
        except:
            print('File error')

    elif command[0] == 'j':
        '''Prints the AST_file (Pretty Print) of the currently stored program (command p) slice.
        O(s)'''
        ident=0
        is_value=False
        print_json(AST_current,ident,is_value)
        
    elif command[0] == 'x':
        '''Exit the program.  
        O(1)'''
        print('\nExit\n')

    else:
        print('\nCommand not valid\n')
