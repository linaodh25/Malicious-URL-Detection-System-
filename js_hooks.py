# Inject a spy into the page BEFORE it loads to catch 
# Any Dangerous Javascript 

def inject_hooks(page) : 
    # Get any Script 
    spy_script = get_spy_script()

    # Inject before Page loads 
    page.add_init_script(spy_script)

    print("JS Hoocks Injected!")


def get_js_events(page) : 
    try : 
        # Read Spy notebook from page
        js_events = page.evaluate("""
            () => {
                return {
                    eval_calls : window.__spy.eval_calls , 
                    dom_writes : window.__spy.dom_writes , 
                    popups : window.__spy.popups , 
                    form_submissions : window.__spy.form_submissions 
                                  
                }
        
        }
        """)

        print(f"eval calls : {len(js_events['eval_calls'])}")
        print(f"dom writes : {len(js_events['dom_writes'])}")
        print(f"popups : {len(js_events['popups'])}")
        print(f"form submissions : {len(js_events['form_submissions'])}")

        return js_events 
    
    except : 
        return {
            "eval_calls" : [] , 
            "dom_writes" : [] , 
            "popups" : [] , 
            "form_submissions" : []

        }
 
 










# This Fucntion is not doing any thing , 
# Just Prepare String that contains 
# JS code that will be injected 

def get_spy_script() : 
    # we put it on the Browser , globally so we can access it at any time 
    storage = """
        window.__spy = {
            eval_calls : [] , 
            dom_writes : [] , 
            popups : [] , 
            form_submissions : []
        };
    """ 

    # Window Eval :may contains the malicious code ( Well but how did we get it )
    # place teh malicious code on the real_eval variable
    # Update the eval function , so it push the code to us ( so we examine it )
    eval_hook = """
        const _real_eval = window.eval ; 
        window.eval = function(code) {
            window.__spy.eval_calls.push(String(code)); 
            return _real_eval(code) ;
        }; 
    """

    write_hook = """
        const _real_write = document.write.bind(document) ; 
        document.write = function(html) {
            window.__spy.dom_writes.push(String(html)) ; 
            return _real_write(html) ; 
        }; 
    """

    popup_hook = """
        window.alert = function(message) {
            window.__spy.popups.push(String(message)) ; 
        };

        window.confirm = function(message) {
            window.__spy.popups.push(String(message))
        };

        window.prompt = function(message) {
            window.__spy.popups.push(String(message)) ; 
            return null ; 
        }
    """

    form_hook = """
        document.addEventListener("submit" , function(event) {
            const form = event.target ; 
            const action = form.action || "unknown" ; 
            const fields = [] ; 
            for (const input of form.elements) {
                if(input.name) {
                fields.push(input.name) ; 
                }
            }

            window.__spy.form_submissions.push({
                action : action , 
                fields : fields 
            }) ; 

        }); 
        """
    

    # Combine all parts 
    return storage + eval_hook + write_hook + popup_hook + form_hook

